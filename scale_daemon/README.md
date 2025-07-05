# Scale Daemon

This application connects to a serial-connected laboratory scale, reads its output, and publishes the data to an MQTTv5 broker. It also subscribes to a command topic to receive single-byte commands to send to the scale.

## Features

- **MQTTv5 Support**: Utilizes MQTT version 5 with QoS 2 for reliable messaging.
- **TLS and Authentication**: Connects to the MQTT broker using TLSv1.2/1.3 and username/password authentication.
- **Resilient Connections**: Automatically retries and reconnects to both the serial port and the MQTT broker in case of failures.
- **Environment-based Configuration**: All settings are managed through environment variables, with sensible defaults.

## Prerequisites

- Python 3.12+
- pip (Python package installer)
- A serial-connected scale or an emulated device.
- Access to an MQTTv5 broker.

## Installation

### Option 1: Local Development Installation

1. **Clone the repository** (or receive this directory).
2. **Navigate to the `scale_daemon` directory**:

    ```bash
    cd scale_daemon
    ```

3. **Install the package in development mode**:

    ```bash
    pip install -e .
    ```

4. **For development dependencies**, install them separately:

    ```bash
    pip install -r requirements-dev.txt
    ```

### Option 2: System-wide Installation with pipx (Recommended for CLI tools)

1. **Install pipx** if you haven't already:

    ```bash
    pip install pipx
    ```

2. **Navigate to the `scale_daemon` directory**:

    ```bash
    cd scale_daemon
    ```

3. **Install the daemon using pipx**:

    ```bash
    pipx install .
    ```

### Option 3: Direct pip installation

1. **Navigate to the `scale_daemon` directory**:

    ```bash
    cd scale_daemon
    ```

2. **Install the package**:

    ```bash
    pip install .
    ```

## Configuration

The daemon is configured entirely through environment variables. You can create a `.env` file in this directory to manage your settings.

| Environment Variable      | Description                               | Default Value                  |
| ------------------------- | ----------------------------------------- | ------------------------------ |
| `SERIAL_DEVICE_PATH`      | Path to the serial device for the scale.  | `/dev/ttyUSB_SCALE`            |
| `SERIAL_BAUDRATE`         | Baud rate for the serial connection.      | `9600`                         |
| `MQTT_BROKER_HOST`        | MQTT broker hostname or IP address.       | `mqtt.example.com`             |
| `MQTT_BROKER_PORT`        | MQTT broker port.                         | `8883`                         |
| `MQTT_USERNAME`           | Username for MQTT authentication.         | `scale_user`                   |
| `MQTT_PASSWORD`           | Password for MQTT authentication.         | `scale_password`               |
| `MQTT_USE_TLS`            | Set to `true` or `false` to enable/disable TLS. | `true`                         |
| `MQTT_DATA_TOPIC`         | Topic for publishing scale data.          | `laboratory/scale/data`        |
| `MQTT_COMMAND_TOPIC`      | Topic for receiving commands for the scale. | `laboratory/scale/command`     |
| `MOCK_SERIAL_DEVICES`     | Set to `true` to use a mock serial device for testing without hardware. | `false` |

**Example `.env` file:**

```dotenv
# .env
SERIAL_DEVICE_PATH=/dev/ttyS0
MQTT_BROKER_HOST=localhost
MQTT_BROKER_PORT=1883
MQTT_USERNAME=my_user
MQTT_PASSWORD=my_secret_password
MQTT_USE_TLS=false
```

## Running the Daemon

Once configured, you can run the daemon using one of these methods:

### If installed with pipx

```bash
scale-daemon
```

### If installed with pip (development mode)

```bash
scale-daemon
```

### If running from source without installation

```bash
python -m scale_daemon.main
```

The application will start, connect to the serial device and the MQTT broker, and begin processing data.

## Running Unit Tests

To run the suite of unit tests, execute the following command:

### If you installed development dependencies

```bash
pytest
```

### Or run tests from the source directory

```bash
python -m pytest
