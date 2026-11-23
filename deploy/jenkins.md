# Jenkins deployment to the Raspberry Pi

The root `Jenkinsfile` checks `main` approximately every two minutes, verifies the checkout, builds native ARM64 images on the Pi, and deploys the existing `private-vault` Compose project. Jenkins can remain on your private network: no GitHub webhook or public Jenkins port is required. Run the job manually once to register polling. A push to `main` then schedules subsequent builds.

## One-time Pi agent setup

Keep the existing Jenkins controller container. Configure a dedicated **host agent** on the Pi, using Jenkins' SSH Build Agents plugin. This avoids installing Docker and build tools inside the controller or mounting the Docker socket into it. Jenkins must be able to SSH to the Pi host from its container.

Create a dedicated account and workspace on the Pi:

```sh
sudo adduser --disabled-password --gecos '' vault-ci
sudo usermod -aG docker vault-ci
sudo install -d -o vault-ci -g vault-ci -m 0700 /var/lib/private-vault-ci
sudo touch /opt/private-vault/.deploy.lock
sudo chown vault-ci:vault-ci /opt/private-vault/.deploy.lock
sudo chmod 0600 /opt/private-vault/.deploy.lock
sudo chgrp vault-ci /opt/private-vault/.env.pi
sudo chmod 0640 /opt/private-vault/.env.pi
```

Preserve the existing `.env.pi` values, particularly hostname, LAN address, and reviewed base-image digests. Do not copy the staging example over a live configuration. `/opt/private-vault` must be traversable by the agent. Configuration stays outside the Jenkins checkout; the script fixes the Compose project name to preserve `private-vault_vault_data` and both Caddy volumes. If your deployment uses another project name or configuration path, adapt the script before enabling this job.

Provision the agent host with Git, a Java runtime supported by your Jenkins version, Node.js 20+ and npm, Python 3.11+, `age`, `curl`, Docker Engine and a current Compose plugin supporting `up --wait`. Install stable Rust with rustfmt and Clippy **as `vault-ci`**, plus `cargo +stable install cargo-audit --locked`. Make the user's Cargo bin directory available in the agent's PATH (for this account, `/home/vault-ci/.cargo/bin`). Confirm all commands work in the noninteractive SSH environment. Tool downloads need outbound HTTPS.

In **Manage Jenkins → Nodes → New Node**, create a permanent agent:

- Remote root: `/var/lib/private-vault-ci`; one executor.
- Label: `private-vault-pi`; usage: only jobs matching the label.
- Launch via SSH to the Pi host, as `vault-ci`, with a dedicated SSH credential stored in Jenkins.
- Pin the Pi's SSH host key using Jenkins' known-hosts or manually supplied key verification strategy; verify its fingerprint through your existing trusted SSH connection.

Install the matching public SSH key in `/home/vault-ci/.ssh/authorized_keys` (directory mode 0700, file mode 0600, owned by `vault-ci`). Keep the private key in Jenkins credentials. Do not disable host-key verification. Set the controller's built-in executor count to zero.

**Trust boundary:** Docker group access is effectively Pi root access. Anyone who can modify the Jenkinsfile, deployment script, or trusted `main` code can control this host and its vault volumes. Restrict repository writes and Jenkins job configuration; protect `main`. Never run pull requests, forks, or unrelated jobs on this agent. A label is scheduling configuration, not an authorization boundary. Restrict which Jenkins users can create/configure jobs; use a separate agent/host for untrusted builds.

## Create the Jenkins job

Create one ordinary **Pipeline** job (not a multibranch/PR job), named `private-vault-main`:

1. Choose **Pipeline script from SCM → Git** and your repository URL. For a private repo, store a read-only GitHub credential in Jenkins.
2. Set the branch specifier to `*/main`, remote name `origin`, and refspec to `+refs/heads/main:refs/remotes/origin/main`. Enable “Honor refspec on initial clone” if available. Script path: `Jenkinsfile`.
3. Save and run **Build Now** once. Future main changes are detected by polling. Do not enable this same deployment in a second job: concurrent runs are queued within this job; a host file lock also rejects overlapping script deployments.

The checkout is disposable and cleaned each build; keep no secrets there. The revision check catches accidental non-main checkouts; restricting the job's SCM configuration and repository permissions establishes trust before Jenkins executes the Jenkinsfile.

## Deployment behavior and recovery

The job runs client tests/build and npm audit, vendored-source verification, Rust formatting/Clippy/tests/audit, and Python tests. All gates must pass before building deployment images. The existing GitHub checks continue independently. Rust compilation uses one worker to reduce Pi load; builds can still consume substantial RAM, disk, and time. Prefer an SSD and monitor resource use alongside Jenkins and the live vault. The initial build can exceed the two-hour job timeout on a slow Pi; adjust after measuring.

Before the first rollout, verify a fresh **off-Pi encrypted backup** using the existing Mac collector and recovery procedure. Keep this backup process running independently of Jenkins. No production database or private CA is copied into build artifacts.

Images are tagged with the full Git commit. Both images build before stopping the API. The script stops the API, runs migrations under its exclusive database lock, recreates services, and checks `/health` using Caddy's existing public CA certificate and hostname verification. It never deletes volumes, runs `init`/`recover`, or prunes images. API sessions expire on restart; a brief outage is expected. The host-side HTTPS check does not replace a LAN/VPN check from a client.

If build or tests fail, running containers are untouched. If migration fails, the API stays stopped and Jenkins fails. If startup/HTTPS fails, Jenkins fails and services may be partially running. Do not blindly retry destructive recovery commands or automatically roll back an image across schema changes. Review the failed stage and container status privately, fix forward, or restore a verified backup using the recovery guide. The deployment is not atomic across services.

For a compatible-schema manual image rollback, use your existing `vault_pi` commands with the previous commit's image tags in `.env.pi`, with the API stopped during any required maintenance. Automatic builds override these image tags for their own invocation only; they do not rewrite `.env.pi`. After a successful rollout, update the file's `VAULT_API_IMAGE` and `VAULT_PROXY_IMAGE` to the deployed commit tags before manual `up` commands. Retain previous images until recovery is confirmed; monitor disk rather than running global Docker prune on a host shared with Jenkins.

Local tests mock Docker commands to verify deployment ordering and failure handling. Actual Jenkins execution, ARM64 builds, migrations against your live data, and Pi networking require validation on your installation.

References: [Jenkins Pipeline syntax](https://www.jenkins.io/doc/book/pipeline/syntax/), [Compose up](https://docs.docker.com/reference/cli/docker/compose/up/).
