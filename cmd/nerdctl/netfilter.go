package main

import (
	"encoding/json"
	"fmt"
	"regexp"

	policy "github.com/containerd/containerd/api/services/auth/proto"
	"github.com/containerd/containerd/api/services/tasks/v1"
	"github.com/containerd/containerd/netpolicy"
	"github.com/containerd/nerdctl/pkg/labels"
	"github.com/containerd/nerdctl/pkg/sessionutil"
	"github.com/davecgh/go-spew/spew"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"
)

func newNetfilterCommand() *cobra.Command {
	netCmd := &cobra.Command{
		Use:   "netfilter",
		Short: "set container network policys",
		RunE:  netAction,
	}
	netCmd.Flags().StringArrayP("input", "i", []string{}, "set input rules json: { \"ip\": \"192.168.17.0/24\", \"port\":\"80\", \"action\":\"drop\", \"protocol\":\"tcp\" }")
	netCmd.Flags().BoolP("default_drop", "d", false, "input/output default drop policy, default accept all")
	netCmd.Flags().StringArrayP("output", "o", []string{}, "set output rules json: { \"ip\": \"192.168.17.25/32\", \"port\":\"80-8080\", \"action\":\"accept\" }")

	return netCmd
}

func netAction(cmd *cobra.Command, args []string) error {
	if len(args) == 0 {
		return errors.Errorf("requires at least 1 argument")
	}

	client, ctx, cancel, err := newClient(cmd)
	if err != nil {
		return err
	}
	defer cancel()
	if err := sessionutil.CheckSession(ctx, client); err != nil {
		return err
	}

	inputs, err := cmd.Flags().GetStringArray("input")
	ouputs, err := cmd.Flags().GetStringArray("output")
	defaultDrop, err := cmd.Flags().GetBool("default_drop")
	if err != nil {
		return err
	}

	ips := []*Rule{}
	ops := []*Rule{}
	for _, i := range inputs {
		r := &Rule{}
		if err := json.Unmarshal([]byte(i), r); err != nil {
			return err
		}
		ips = append(ips, r)
	}

	for _, o := range ouputs {
		r := &Rule{}
		if err := json.Unmarshal([]byte(o), r); err != nil {
			return err
		}
		ops = append(ops, r)
	}

	group := generateGroup(defaultDrop, ips, ops)
	fmt.Println(spew.Sdump(group))

	pls, err := netpolicy.ParseGroup(group)
	if err != nil {
		return err
	}

	r, err := json.Marshal(pls)
	if err != nil {
		return err
	}

	filters := []string{
		fmt.Sprintf("labels.%q==%s", labels.Name, args[0]),
		fmt.Sprintf("id~=^%s.*$", regexp.QuoteMeta(args[0])),
	}

	containers, err := client.Containers(ctx, filters...)
	if err != nil {
		return err
	}

	fmt.Println(string(r))

	for _, c := range containers {
		// labels, err := c.Labels(ctx)
		// if err != nil {
		// 	return err
		// }
		// fmt.Println(spew.Sdump(c))

		id := c.ID()
		if _, err := client.TaskService().SetNetPolicy(ctx, &tasks.SetNetPolicyRequest{
			ID: id,
			Netpolicy: &tasks.NetPolicy{
				Policys: string(r),
			},
		}); err != nil {
			return err
		}
	}

	return nil
}

type Rule struct {
	IP       string `json:"ip"`
	Port     string `json:"port"`
	Action   string `json:"action"`
	Protocol string `json:"protocol"`
}

func generateGroup(defaultDrop bool, input, output []*Rule) *policy.PolicyGroup {
	d := policy.NetPolicyAccessType_Permit
	if defaultDrop {
		d = policy.NetPolicyAccessType_Deny
	}

	group := &policy.PolicyGroup{
		Default:       d,
		NetworkPolicy: []*policy.NetPolicy{},
	}

	for _, i := range input {
		p := policy.NetPolicyProtocol_TCP
		if i.Protocol == "udp" {
			p = policy.NetPolicyProtocol_UDP
		}
		a := policy.NetPolicyAccessType_Permit
		if i.Action == "drop" {
			a = policy.NetPolicyAccessType_Deny
		}
		n := &policy.NetPolicy{
			Type:       policy.NetPolicyType_Segment,
			Protocol:   p,
			AccessType: a,
			Direction:  policy.PolicyDirection_Input,
			Value:      i.IP,
			Port:       i.Port,
			IsActive:   true,
		}
		group.NetworkPolicy = append(group.NetworkPolicy, n)
	}

	for _, o := range output {
		p := policy.NetPolicyProtocol_TCP
		if o.Protocol == "udp" {
			p = policy.NetPolicyProtocol_UDP
		}
		a := policy.NetPolicyAccessType_Permit
		if o.Action == "drop" {
			a = policy.NetPolicyAccessType_Deny
		}
		n := &policy.NetPolicy{
			Type:       policy.NetPolicyType_Segment,
			Protocol:   p,
			AccessType: a,
			Direction:  policy.PolicyDirection_Output,
			Value:      o.IP,
			Port:       o.Port,
			IsActive:   true,
		}
		group.NetworkPolicy = append(group.NetworkPolicy, n)
	}

	return group
}
