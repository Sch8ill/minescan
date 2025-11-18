package sys

import (
	"fmt"
	"os/exec"
	"os/user"
	"strconv"
)

const iptablesPath = "/usr/sbin/iptables"

// ConfigureFirewall configures iptables to drop all outgoing RST packets not originating
// from this uid, therefore preventing a connection reset by the kernel which it is not
// aware of any of our connections.
// sudo iptables -A OUTPUT -p tcp --sport <port> --tcp-flags RST RST -m owner ! --uid-owner <uid> -j DROP
func ConfigureFirewall(srcPort uint16) error {
	cmd, err := iptablesCmd("-A", srcPort)
	if err != nil {
		return err
	}

	stdout, err := exec.Command("sudo", cmd...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("iptables: block kernel RST: %w: %s", err, string(stdout))
	}

	return nil
}

// RevertFirewall deletes the previously set iptables rule.
func RevertFirewall(srcPort uint16) error {
	cmd, err := iptablesCmd("-D", srcPort)
	if err != nil {
		return err
	}

	stdout, err := exec.Command("sudo", cmd...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("revert iptables changes: %w: %s", err, string(stdout))
	}

	return nil
}

func iptablesCmd(action string, port uint16) ([]string, error) {
	user, err := user.Current()
	if err != nil {
		return nil, fmt.Errorf("get uid: %w", err)
	}

	return []string{
		iptablesPath,
		action, "OUTPUT",
		"-p", "tcp",
		"--sport", strconv.FormatUint(uint64(port), 10),
		"--tcp-flags", "RST", "RST",
		"-m", "owner", "!", "--uid-owner", user.Uid,
		"-j", "DROP",
	}, nil
}
