package main

import (
	"archive/tar"
	"context"
	"fmt"
	"github.com/containerd/containerd"
	"github.com/containerd/containerd/cio"
	"github.com/containerd/containerd/cmd/ctr/commands"
	"github.com/containerd/nerdctl/pkg/idgen"
	"github.com/containerd/nerdctl/pkg/idutil/containerwalker"
	"github.com/containerd/nerdctl/pkg/taskutil"
	"github.com/docker/docker/pkg/system"
	"github.com/google/uuid"
	"github.com/opencontainers/runtime-spec/specs-go"
	"github.com/spf13/cobra"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

func NewCpCommand() *cobra.Command {
	var cpCommand = &cobra.Command{
		Use:   "cp",
		Args:  cobra.ExactValidArgs(2),
		Short: "Copy file from local filesystem to container",
		RunE:  cpAction,
	}
	return cpCommand
}

func cpAction(cmd *cobra.Command, args []string) error {
	// parse args
	if args[0] == "" {
		return fmt.Errorf("source can not be empty")
	}
	source := args[0]

	if args[1] == "" {
		return fmt.Errorf("destination can not be empty")
	}
	destination := args[1]

	srcContainer, srcPath := splitCpArg(source)
	if srcContainer != "" {
		return fmt.Errorf("count not copy from container")
	}

	destContainer, destPath := splitCpArg(destination)
	if destContainer == "" {
		return fmt.Errorf("container name could not be empty")
	}

	client, ctx, cancel, err := newClient(cmd)
	if err != nil {
		return err
	}
	defer cancel()
	walker := &containerwalker.ContainerWalker{
		Client: client,
		OnFound: func(ctx context.Context, found containerwalker.Found) error {
			if found.MatchIndex > 1 {
				return fmt.Errorf("ambiguous ID %q", found.Req)
			}
			return copyActionWithContainer(ctx, srcPath, destPath, found.Container)
		},
	}
	req := destContainer
	n, err := walker.Walk(ctx, req)
	if err != nil {
		return err
	} else if n == 0 {
		return fmt.Errorf("no such container %s", req)
	}
	return nil
}

func copyActionWithContainer(ctx context.Context, srcPath, destPath string, container containerd.Container) error {
	pspec, err := generateCpProcessSpec(ctx, destPath, container)
	if err != nil {
		return err
	}

	task, err := container.Task(ctx, nil)
	if err != nil {
		return err
	}

	tarName, err := prepareArchive1(srcPath)
	if err != nil {
		return err
	}
	tarReader, err := os.Open(tarName)
	if err != nil {
		return err
	}
	defer func() {
		if err := tarReader.Close(); err != nil {
			fmt.Println("close tar reader failed with error", err.Error())
		}
		os.RemoveAll(tarName)
	}()

	if err != nil {
		return err
	}
	var (
		ioCreator cio.Creator
		in        io.Reader
		stdinC    = &taskutil.StdinCloser{
			Stdin: tarReader,
		}
	)
	in = stdinC
	//in = tarReader

	cioOpts := []cio.Opt{cio.WithStreams(in, os.Stdout, os.Stderr)}
	ioCreator = cio.NewCreator(cioOpts...)

	execID := "exec-" + idgen.GenerateID()
	process, err := task.Exec(ctx, execID, pspec, ioCreator)
	if err != nil {
		return err
	}

	stdinC.Closer = func() {
		process.CloseIO(ctx, containerd.WithStdinCloser)
	}
	defer process.Delete(ctx)

	statusC, err := process.Wait(ctx)
	if err != nil {
		return err
	}

	sigc := commands.ForwardAllSignals(ctx, process)
	defer commands.StopCatch(sigc)

	if err := process.Start(ctx); err != nil {
		return err
	}

	status := <-statusC
	code, _, err := status.Result()

	if err != nil {
		return err
	}

	if code != 0 {
		return fmt.Errorf("copy failed with exit code %d", code)
	}
	return nil
}

func prepareArchive(srcPath string) (io.ReadCloser, error) {
	// if source file not exist, return error to stop copy
	stat, err := os.Stat(srcPath)
	if err != nil {
		return nil, err
	}

	pipeReader, pipeWriter := io.Pipe()
	tw := tar.NewWriter(pipeWriter)
	go func() {
		defer func() {
			//fmt.Println("close tw, pipe writer")
			if err := tw.Close(); err != nil {
				fmt.Println("can not close tar writer: ", err.Error())
			}
			if err := pipeWriter.CloseWithError(nil); err != nil {
				fmt.Println("can not close pipe writer: ", err.Error())
			} else {
				fmt.Println("pipe writer closed")
			}
		}()

		if stat.IsDir() {
			err := filepath.Walk(srcPath, func(fileName string, fi fs.FileInfo, err error) error {
				if err != nil {
					return err
				}

				hdr, err := tar.FileInfoHeader(fi, "")
				if err != nil {
					return err
				}

				hdr.Name = strings.TrimPrefix(fileName, string(filepath.Separator))
				if err := tw.WriteHeader(hdr); err != nil {
					return err
				}

				if !fi.Mode().IsRegular() {
					return nil
				}

				fr, err := os.Open(fileName)
				if err != nil {
					return err
				}
				defer fr.Close()

				_, err = io.Copy(tw, fr)
				if err != nil {
					return err
				}
				return nil
			})
			if err != nil {
				return
			}
		} else {
			hdr, err := tar.FileInfoHeader(stat, "")
			err = tw.WriteHeader(hdr)
			if err != nil {
				return
			}

			fr, err := os.Open(srcPath)
			if err != nil {
				return
			}
			defer fr.Close()

			n, err := io.Copy(tw, fr)
			if err != nil {
				return
			}
			fmt.Printf("copy %d bytes\n", n)
		}
	}()

	return pipeReader, nil
}

func prepareArchive1(srcPath string) (string, error) {
	// if source file not exist, return error to stop copy
	stat, err := os.Stat(srcPath)
	if err != nil {
		return "", err
	}
	tmpName := fmt.Sprintf("/tmp/dacs-tar-%s", uuid.NewString())
	fw, err := os.Create(tmpName)
	if err != nil {
		return "", err
	}

	tw := tar.NewWriter(fw)

	defer func() {
		//fmt.Println("close tw, pipe writer")
		if err := tw.Close(); err != nil {
			fmt.Println("can not close tar writer: ", err.Error())
		}
		if err := fw.Close(); err != nil {
			fmt.Println("close tmp file failed")
		}
	}()

	if stat.IsDir() {
		var totalCount int64 = 0
		err := filepath.Walk(srcPath, func(fileName string, fi fs.FileInfo, err error) error {
			if err != nil {
				return err
			}

			hdr, err := tar.FileInfoHeader(fi, "")
			if err != nil {
				return err
			}

			hdr.Name = strings.TrimPrefix(fileName, string(filepath.Separator))
			if err := tw.WriteHeader(hdr); err != nil {
				return err
			}

			if !fi.Mode().IsRegular() {
				return nil
			}

			fr, err := os.Open(fileName)
			if err != nil {
				return err
			}
			defer fr.Close()

			n, err := io.Copy(tw, fr)
			totalCount += n
			if err != nil {
				return err
			}
			return nil
		})
		if err != nil {
			return "", err
		}

		fmt.Printf("copy %d bytes\n", totalCount)
	} else {
		hdr, err := tar.FileInfoHeader(stat, "")
		err = tw.WriteHeader(hdr)
		if err != nil {
			return "", err
		}

		fr, err := os.Open(srcPath)
		if err != nil {
			return "", err
		}
		defer fr.Close()

		n, err := io.Copy(tw, fr)
		if err != nil {
			return "", err
		}
		fmt.Printf("copy %d bytes\n", n)
	}

	return tmpName, nil
}

func generateCpProcessSpec(ctx context.Context, destPath string, container containerd.Container) (*specs.Process, error) {
	spec, err := container.Spec(ctx)
	if err != nil {
		return nil, err
	}

	pspec := spec.Process
	pspec.Args = []string{
		"tar", "-xf", "-", "-C", destPath,
	}

	return pspec, nil

}

func splitCpArg(arg string) (container, path string) {
	if system.IsAbs(arg) {
		return "", arg
	}

	parts := strings.SplitN(arg, ":", 2)
	if len(parts) == 1 || strings.HasPrefix(parts[0], ".") {
		return "", arg
	}
	return parts[0], parts[1]
}
