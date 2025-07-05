# Scale and Printer MQTT Adapter

This project provides two Python daemons to connect a laboratory scale and an ESC/POS line printer over the network using MQTTv5.

- **Scale Daemon**: Reads data from a serial-connected scale, processes it, and publishes messages to an MQTT topic. It also listens on another MQTT topic for single-byte commands to send to the scale.
- **Printer Daemon**: Subscribes to an MQTT topic (where the scale daemon publishes data) and prints received messages to a serial-connected ESC/POS printer.

## Features

- **Python 3.12+**: Modern Python implementation.
- **Poetry**: Dependency management and packaging.
- **MQTTv5**: Utilizes MQTT version 5 with QoS 2 for reliable messaging.
- **TLS Support**: Connects to the MQTT broker using TLSv1.2/1.3 with basic username/password authentication.
- **Resilient Connections**: Implements retry and reconnection mechanisms for both serial and MQTT connections.
- **Threaded Architecture**: Each daemon uses separate threads for serial communication and MQTT handling, with thread-safe queues for inter-thread communication.
- **Containerized**: Includes `Containerfile`s for building multi-arch (x86_64, arm64) Docker/Podman images using Alpine Linux. Unit tests are run during the image build process.
- **Kubernetes Ready**: A Helm chart is provided for deployment in a Kubernetes environment, including considerations for node affinity and host device access.
- **CI/CD**: GitHub Actions workflows for:
  - Building images, running unit tests, and basic integration tests on push/pull_request.
  - Publishing images to GHCR on new releases.

## Project Structure

```tree
scale-printer-mqtt/
├── .github/
│   ├── workflows/            # GitHub Actions CI/CD
│   │   ├── build-test.yml
│   │   └── publish.yml
│   └── dependabot.yml        # Dependabot configuration (to be added)
├── helm_chart/
│   └── scale-printer-mqtt/   # Helm chart for Kubernetes deployment
├── mosquitto/
│   └── config/               # Configuration for local Mosquitto (integration tests)
├── printer_daemon/           # Source code and tests for the printer daemon
│   ├── src/printer_daemon/
│   ├── tests/
│   ├── Containerfile
│   └── pyproject.toml
├── scale_daemon/             # Source code and tests for the scale daemon
│   ├── src/scale_daemon/
│   ├── tests/
│   ├── Containerfile
│   └── pyproject.toml
├── docker-compose.yml        # For local integration testing
├── LICENSE                   # Project license (to be added)
└── README.md                 # This file
```

## Prerequisites

- Python 3.12+
- Poetry
- Docker or Podman (for building and running containers)
- Access to an MQTTv5 broker (or use the provided `docker-compose.yml` for a local one)
- Serial devices (scale and printer) or emulated equivalents. Udev rules should be configured on host systems to provide stable device paths (e.g., `/dev/ttyUSB_SCALE`, `/dev/ttyUSB_PRINTER`).

## Local Development and Testing

This section provides instructions for setting up and running the daemons on your local machine for development or testing purposes.

### 1. Install Dependencies

Navigate to each daemon's directory and install dependencies using Poetry:

```bash
cd scale_daemon
poetry install
cd ../printer_daemon
poetry install
cd ..
```

### 2. Configure Environment

The daemons are configured using environment variables. The following variables are available, with default values used if not set:

| Environment Variable  | Description                                                            | Default Value                                |
| --------------------- | ---------------------------------------------------------------------- | -------------------------------------------- |
| `MQTT_BROKER_HOST`    | MQTT broker hostname or IP address.                                    | `mqtt.example.com`                           |
| `MQTT_BROKER_PORT`    | MQTT broker port.                                                      | `8883`                                       |
| `MQTT_USERNAME`       | Username for MQTT authentication.                                      | `scale_user`/`printer_user`                  |
| `MQTT_PASSWORD`       | Password for MQTT authentication.                                      | `scale_password`/`printer_password`          |
| `MQTT_USE_TLS`        | Set to `true` or `false` to enable/disable TLS.                        | `true`                                       |
| `MQTT_DATA_TOPIC`     | Topic for publishing scale data.                                       | `laboratory/scale/data`                      |
| `MQTT_COMMAND_TOPIC`  | Topic for receiving commands for the scale.                            | `laboratory/scale/command`                   |
| `MQTT_PRINT_TOPIC`    | Topic the printer subscribes to.                                       | `laboratory/scale/data`                      |
| `SERIAL_DEVICE_PATH`  | Path to the serial device.                                             | `/dev/ttyUSB_SCALE` or `/dev/ttyUSB_PRINTER` |
| `MOCK_SERIAL_DEVICES` | Set to `true` to use mock serial devices for testing without hardware. | `false`                                      |

Create a `.env` file in the root of the project to manage your local configuration. For example:

```dotenv
# .env
MQTT_BROKER_HOST=localhost
MQTT_BROKER_PORT=1883
MQTT_USERNAME=scale_user
MQTT_PASSWORD=your_scale_password
MQTT_USE_TLS=false
MOCK_SERIAL_DEVICES=true
```

### 3. Running the Daemons Locally

You can run each daemon directly using Poetry's script runner:

```bash
# Terminal 1: Scale Daemon
cd scale_daemon
poetry run scale-daemon

# Terminal 2: Printer Daemon
cd printer_daemon
poetry run printer-daemon
```

### 4. Building and Running with Docker/Podman

Each daemon has a `Containerfile` for building an image.

```bash
# Build scale daemon image
podman build -t scale-daemon-app -f scale_daemon/Containerfile ./scale_daemon

# Build printer daemon image
podman build -t printer-daemon-app -f printer_daemon/Containerfile ./printer_daemon
```

To run the containers, you'll need to map the serial devices from your host and potentially set environment variables if you adapt the code to use them for configuration (currently uses hardcoded constants).

Example (Podman, assuming devices `/dev/ttyUSB_SCALE` and `/dev/ttyUSB_PRINTER` exist on host):

```bash
# Run scale daemon container
podman run -d --rm --name scale_daemon_instance --device /dev/ttyUSB_SCALE:/dev/ttyUSB_SCALE:rwm scale-daemon-app

# Run printer daemon container
podman run -d --rm --name printer_daemon_instance --device /dev/ttyUSB_PRINTER:/dev/ttyUSB_PRINTER:rwm printer-daemon-app
```

*Note: `--device` mapping and permissions might require running Podman/Docker with sufficient privileges or specific SELinux/AppArmor configurations.*

### 4. Running Unit Tests

Run unit tests from within each daemon's directory:

```bash
# For the scale daemon
cd scale_daemon
poetry run pytest

# For the printer daemon
cd printer_daemon
poetry run pytest
```

### 5. Integration Testing with Docker Compose

A `compose.yaml` file is provided to run a full integration test suite, including a Mosquitto MQTT broker.

**Setup:**

1. **Generate MQTT Credentials**: The Mosquitto broker requires a password file. Create it with the users `scale_user` and `printer_user`.

    ```bash
    mkdir -p mosquitto/config
    mosquitto_passwd -c -b mosquitto/config/mosquitto_passwd scale_user your_scale_password
    mosquitto_passwd -b mosquitto/config/mosquitto_passwd printer_user your_printer_password
    ```

    *(Replace `your_..._password` with secure passwords)*

2. **Configure Test Environment**: Create a `.env` file in the project root and set the following variables:

    ```dotenv
    # .env for integration testing
    MOCK_SERIAL_DEVICES=true
    RUN_INTEGRATION_TEST=true
    MQTT_PASSWORD_SCALE=your_scale_password
    MQTT_PASSWORD_PRINTER=your_printer_password
    ```

**Run the Test:**

Execute the following command to build the images and run the tests:

```bash
docker-compose -f compose.yaml up --build --abort-on-container-exit
```

The test script within the `scale-daemon` will run, and the exit code will indicate success (0) or failure (non-zero).

### 6. Systemd Service Installation

For production deployment on Linux systems, you can install the daemons as systemd services using Podman containers. This provides automatic startup, restart on failure, and integration with the system service manager.

#### EL Prerequisites

- RHEL/CentOS/Fedora or similar systemd-based Linux distribution
- Podman installed and configured
- Root access for system service installation
- USB serial devices connected (scale and printer)

#### Step 1: Install Udev Rules

First, install the udev rules to create persistent device names:

```bash
# Copy the udev rules file
sudo cp udev/99-usb-serial-devices.rules /etc/udev/rules.d/

# Reload udev rules
sudo udevadm control --reload-rules
sudo udevadm trigger

# Verify device symlinks are created (after connecting devices)
ls -la /dev/ttyUSB_*
```

**Important**: Edit `/etc/udev/rules.d/99-usb-serial-devices.rules` to match your actual device VID/PID values. Use `lsusb` to identify your devices:

```bash
# Find your USB-to-serial devices
lsusb | grep -E "(FTDI|Prolific|Silicon|QinHeng)"

# Get detailed device information
udevadm info -a -p $(udevadm info -q path -n /dev/ttyUSB0)
```

#### Step 2: Configure Environment Variables

Create environment configuration files for each daemon:

```bash
# Scale daemon configuration
sudo cp scale_daemon/scale-daemon.env.example /etc/sysconfig/scale-daemon

# Printer daemon configuration
sudo cp printer_daemon/printer-daemon.env.example /etc/sysconfig/printer-daemon
```

Edit the configuration files with your MQTT broker settings:

```bash
# Edit scale daemon config
sudo nano /etc/sysconfig/scale-daemon

# Edit printer daemon config
sudo nano /etc/sysconfig/printer-daemon
```

#### Step 3: Setup SELinux Policies (if SELinux is enabled)

Generate and install SELinux policies for container device access:

```bash
# Check if SELinux is enabled
getenforce

# If SELinux is enforcing or permissive, install policies
sudo ./selinux/generate-container-policy.sh all

# Alternative: run individual steps
sudo ./selinux/generate-container-policy.sh generate
sudo ./selinux/generate-container-policy.sh install
sudo ./selinux/generate-container-policy.sh contexts
sudo ./selinux/generate-container-policy.sh booleans
```

#### Step 4: Install Systemd Service Files

Install the systemd service unit files:

```bash
# Install scale daemon service
sudo cp scale_daemon/scale-daemon.service /etc/systemd/system/

# Install printer daemon service
sudo cp printer_daemon/printer-daemon.service /etc/systemd/system/

# Reload systemd to recognize new services
sudo systemctl daemon-reload
```

#### Step 5: Enable and Start Services

```bash
# Enable services to start automatically at boot
sudo systemctl enable scale-daemon.service
sudo systemctl enable printer-daemon.service

# Start the services
sudo systemctl start scale-daemon.service
sudo systemctl start printer-daemon.service

# Check service status
sudo systemctl status scale-daemon.service
sudo systemctl status printer-daemon.service
```

#### Service Management Commands

```bash
# View service logs
sudo journalctl -u scale-daemon.service -f
sudo journalctl -u printer-daemon.service -f

# Restart services
sudo systemctl restart scale-daemon.service
sudo systemctl restart printer-daemon.service

# Stop services
sudo systemctl stop scale-daemon.service
sudo systemctl stop printer-daemon.service

# Disable services
sudo systemctl disable scale-daemon.service
sudo systemctl disable printer-daemon.service
```

#### Troubleshooting

1. **Device not found**: Check udev rules and ensure USB devices are connected

   ```bash
   # List USB devices
   lsusb

   # Check udev rule matching
   udevadm test /sys/class/tty/ttyUSB0
   ```

2. **SELinux denials**: Check audit logs and generate additional policies if needed

   ```bash
   # Check for SELinux denials
   sudo ausearch -m avc -ts recent

   # Generate additional policy if needed
   sudo audit2allow -M additional_policy < /var/log/audit/audit.log
   sudo semodule -i additional_policy.pp
   ```

3. **Container fails to start**: Check Podman and systemd logs

   ```bash
   # Check Podman logs
   sudo podman logs scale-daemon

   # Check systemd service logs
   sudo journalctl -u scale-daemon.service
   ```

4. **MQTT connection issues**: Verify network connectivity and credentials

   ```bash
   # Test MQTT connection manually
   mosquitto_pub -h your-mqtt-broker -p 8883 -u scale_user -P your_password -t test -m "hello"
   ```

### 7. Kubernetes Deployment

A Helm chart is located in `helm_chart/scale-printer-mqtt/`.
Refer to the `values.yaml` and `NOTES.txt` within the chart directory for configuration and deployment instructions. You will need to:

- Ensure your Kubernetes nodes have the serial devices accessible.
- Configure `nodeSelector` or `affinity` in `values.yaml` to schedule pods on the correct nodes.
- Ensure the container images are pushed to a registry accessible by your Kubernetes cluster and update `values.yaml` with the correct image repository and tags.
- The chart assumes hostPath for device access, which may require specific cluster permissions and security contexts (`privileged: true` might be needed).

## Development

- **Linting/Formatting**: Black and Flake8 are included as dev dependencies.

    ```bash
    # Inside scale_daemon or printer_daemon directory
    poetry run black src/ tests/
    poetry run flake8 src/ tests/
    ```

- **Pre-commit Hooks**: This project uses `pre-commit` to enforce code quality standards. Install the hooks with:

    ```bash
    pre-commit install
    ```

## License

This project is licensed under the GNU General Public License v2.0 - see the `LICENSE` file for details.
