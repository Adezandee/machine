package provision

import (
	"bytes"
	"fmt"
	"text/template"

	"github.com/docker/machine/libmachine/auth"
	"github.com/docker/machine/libmachine/drivers"
	"github.com/docker/machine/libmachine/engine"
	"github.com/docker/machine/libmachine/log"
	"github.com/docker/machine/libmachine/provision/pkgaction"
	"github.com/docker/machine/libmachine/provision/serviceaction"
	"github.com/docker/machine/libmachine/swarm"
)

func init() {
	Register("Google-Container-VM-Image", &RegisteredProvisioner{
		New: NewGciProvisioner,
	})
}

func NewGciProvisioner(d drivers.Driver) Provisioner {
	return &GciProvisioner{
		GenericProvisioner{
			SSHCommander:      GenericSSHCommander{Driver: d},
			DockerOptionsDir:  "/etc/docker",
			DaemonOptionsFile: "/etc/default/docker",
			OsReleaseID:       "cos",
			Driver: d,
		},
	}
}

type GciProvisioner struct {
	GenericProvisioner
}

func (provisioner *GciProvisioner) String() string {
	return "cos"
}

func (provisioner *GciProvisioner) Service(name string, action serviceaction.ServiceAction) error {
	reloadDaemon := false
	switch action {
	case serviceaction.Start, serviceaction.Restart:
		reloadDaemon = true
	}

	// systemd needs reloaded when config changes on disk; we cannot
	// be sure exactly when it changes from the provisioner so
	// we call a reload on every restart to be safe
	if reloadDaemon {
		if _, err := provisioner.SSHCommand("sudo systemctl daemon-reload"); err != nil {
			return err
		}
	}

	command := fmt.Sprintf("sudo systemctl -f %s %s", action.String(), name)

	if _, err := provisioner.SSHCommand(command); err != nil {
		return err
	}

	return nil
}

func (provisioner *GciProvisioner) Package(name string, action pkgaction.PackageAction) error {
	return nil
}

func (provisioner *GciProvisioner) OpenIptables() error {
	if _, err := provisioner.SSHCommand("sudo iptables -A INPUT -p tcp --dport 2376 -j ACCEPT"); err != nil {
		return err
	}

	return nil
}

func (provisioner *GciProvisioner) GenerateDockerOptions(dockerPort int) (*DockerOptions, error) {
	var (
		engineCfg bytes.Buffer
	)

	driverNameLabel := fmt.Sprintf("provider=%s", provisioner.Driver.DriverName())
	provisioner.EngineOptions.Labels = append(provisioner.EngineOptions.Labels, driverNameLabel)

	engineConfigTmpl := `DOCKER_OPTS=\" \
-H tcp://0.0.0.0:{{.DockerPort}} \
-H unix:///var/run/docker.sock \
--storage-driver {{.EngineOptions.StorageDriver}} \
--tlsverify \
--tlscacert {{.AuthOptions.CaCertRemotePath}} \
--tlscert {{.AuthOptions.ServerCertRemotePath}} \
--tlskey {{.AuthOptions.ServerKeyRemotePath}} \
{{ range .EngineOptions.Labels }}--label {{.}} {{ end }} \
{{ range .EngineOptions.InsecureRegistry }}--insecure-registry {{.}} {{ end }} \
{{ range .EngineOptions.RegistryMirror }}--registry-mirror {{.}} {{ end }} \
{{ range .EngineOptions.ArbitraryFlags }}--{{.}} {{ end }} \
\"
{{range .EngineOptions.Env}}export \"{{ printf "%q" . }}\"{{end}}`
	t, err := template.New("engineConfig").Parse(engineConfigTmpl)
	if err != nil {
		return nil, err
	}

	engineConfigContext := EngineConfigContext{
		DockerPort:    dockerPort,
		AuthOptions:   provisioner.AuthOptions,
		EngineOptions: provisioner.EngineOptions,
	}

	t.Execute(&engineCfg, engineConfigContext)

	return &DockerOptions{
		EngineOptions:     engineCfg.String(),
		EngineOptionsPath: provisioner.DaemonOptionsFile,
	}, nil
}


func (provisioner *GciProvisioner) Provision(swarmOptions swarm.Options, authOptions auth.Options, engineOptions engine.Options) error {
	provisioner.SwarmOptions = swarmOptions
	provisioner.AuthOptions = authOptions
	provisioner.EngineOptions = engineOptions
	provisioner.EngineOptions.StorageDriver = "overlay"
	swarmOptions.Env = engineOptions.Env

	if err := provisioner.SetHostname(provisioner.Driver.GetMachineName()); err != nil {
		return err
	}

	if err := provisioner.OpenIptables(); err != nil {
		return err
	}

	if err := makeDockerOptionsDir(provisioner); err != nil {
		return err
	}

	log.Debugf("Preparing certificates")
	provisioner.AuthOptions = setRemoteAuthOptions(provisioner)

	log.Debugf("Setting up certificates")
	if err := ConfigureAuth(provisioner); err != nil {
		return err
	}

	log.Debug("Configuring swarm")
	if err := configureSwarm(provisioner, swarmOptions, provisioner.AuthOptions); err != nil {
		return err
	}

	return nil
}
