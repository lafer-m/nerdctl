package sessionutil

import (
	"context"
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"strings"

	"github.com/containerd/containerd"
	"github.com/containerd/containerd/api/services/sessions/v1"
)

const (
	UserKey  = "DACSUSER"
	TokenKey = "DACSTOKEN"
	UUIDKey  = "DACSUUID"
)

func CheckSession(ctx context.Context, client *containerd.Client) error {
	sessionID := GetSessionID()
	if sessionID == "" {
		return errors.New("you must setup a session first with `dacsctl session -u ${username} -p ${password}`")
	}

	if _, err := client.SessionService().VerifySession(ctx, &sessions.VerifySessionRequest{ID: sessionID}); err != nil {
		return err
	}

	return nil
}

func GetSessionID() string {
	sID := ""
	f, err := os.Open("/proc/self/stat")
	if err != nil {
		return sID
	}

	content, err := ioutil.ReadAll(f)
	items := strings.Split(string(content), " ")
	sid := items[5]
	uuid := os.Getenv(UUIDKey)
	if uuid == "" {
		return sID
	}
	return fmt.Sprintf("%s_%s", sid, uuid)
}
