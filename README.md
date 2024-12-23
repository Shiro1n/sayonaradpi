# Sayonaradpi

Sayonaradpi is a tool designed for packet manipulation to bypass deep packet inspection (DPI). It leverages network libraries to capture and modify packets in real time.

---

## Features
- Real-time packet capturing and modification.
- Dynamic encryption of packet payloads to evade DPI.
- Automatically selects the active network adapter for operations.

---

## Prerequisites
### Build Environment
- **Operating System:** Windows 11 (preferred for development and testing).
- **Compiler:** GCC (MinGW) or compatible C/C++ compiler.
- **Tools:** CMake, Git, libnet, npcap SDK.

### Dependencies
- **Npcap SDK**: For packet capturing capabilities.
- **Libnet**: For packet construction and forwarding.

Ensure these dependencies are correctly installed and linked to your project.

---

## Installation
1. Clone the repository:
   ```bash
   git clone https://github.com/Shiro1n/sayonaradpi.git
   cd sayonaradpi
   ```
2. Configure the build environment:
   ```bash
   mkdir build && cd build
   cmake ..
   ```
3. Build the project:
   ```bash
   cmake --build .
   ```
4. Run the executable:
   ```bash
   ./sayonaradpi
   ```

---

## Usage
Sayonaradpi automatically selects the active network adapter and begins packet capturing. Captured packets are processed with an encryption mechanism to bypass DPI.

To ensure functionality:
- Verify that Npcap is installed and its services are running.
- Ensure you have proper permissions (run as administrator if required).

---

## Contributing
We welcome contributions! To get started:
1. Fork the repository.
2. Create a new branch for your feature or fix:
   ```bash
   git checkout -b feature-name
   ```
3. Commit your changes:
   ```bash
   git commit -m "Description of your changes"
   ```
4. Push the branch and create a pull request:
   ```bash
   git push origin feature-name
   ```

---

## License
This project is licensed under the MIT License. See the LICENSE file for details.

---

## Acknowledgments
- **Npcap SDK**: For providing robust packet capturing support.
- **Libnet**: For its versatile packet construction library.
- The open-source community for continuous inspiration and support.

---

## Contact
For any issues or feature requests, please create an issue on the [GitHub repository](https://github.com/Shiro1n/sayonaradpi/issues).