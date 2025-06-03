# CoentroVPN Architecture Diagram

```mermaid
graph TD
    subgraph "User Interfaces"
        CLI["CLI Client (cli_client)"]
        GUI["Desktop GUI Client (gui_client)"]
        WebApp["Web Dashboard (dashboard)"]
    end

    subgraph "Backend Services"
        Core["Core VPN Engine (core_engine)"]
        MgmtAPI["Management API (management_api)"]
    end

    subgraph "Shared Components"
        Shared["Shared Utilities (shared_utils)"]
    end

    %% User Client Connections
    CLI -->|Manages VPN Connection| Core
    GUI -->|Manages VPN Connection| Core

    %% Dashboard Interaction
    WebApp -->|Manages Server Config & Monitors| MgmtAPI

    %% Management API Interaction
    MgmtAPI -->|Controls & Configures| Core

    %% Shared Library Usage
    Core --- Shared
    CLI --- Shared
    GUI --- Shared
    MgmtAPI --- Shared

    %% External World
    Internet([Internet])

    Core -->|Secure Tunnel| Internet

    classDef client fill:#D6EAF8,stroke:#3498DB,stroke-width:2px;
    classDef server fill:#D5F5E3,stroke:#2ECC71,stroke-width:2px;
    classDef shared fill:#FCF3CF,stroke:#F1C40F,stroke-width:2px;
    classDef api fill:#EBDEF0,stroke:#8E44AD,stroke-width:2px;

    class CLI,GUI,WebApp client;
    class Core server;
    class MgmtAPI api;
    class Shared shared;
```

## Diagram Legend and Explanation

*   **User Interfaces:**
    *   `CLI Client (cli_client)`: Command-line interface for users to connect to the VPN server and manage their connection.
    *   `Desktop GUI Client (gui_client)`: A graphical user interface for desktop users, providing similar functionality to the CLI client.
    *   `Web Dashboard (dashboard)`: A web-based interface for administrators to monitor server status, manage users (if applicable), and configure server settings. It interacts with the `Management API`.

*   **Backend Services:**
    *   `Core VPN Engine (core_engine)`: The central VPN server responsible for establishing and managing secure tunnels, routing traffic, and handling client connections.
    *   `Management API (management_api)`: An API service that provides endpoints for managing and configuring the `Core VPN Engine`. This is used by the `Web Dashboard`.

*   **Shared Components:**
    *   `Shared Utilities (shared_utils)`: A common library containing shared code, such as networking protocols, cryptographic functions, configuration handling, and logging, used by multiple components of the CoentroVPN system.

*   **Interactions:**
    *   CLI and GUI Clients connect directly to the `Core VPN Engine` to establish VPN sessions.
    *   The `Web Dashboard` communicates with the `Management API` to provide a user-friendly way to manage the VPN server.
    *   The `Management API` interacts with the `Core VPN Engine` to apply configurations and control its behavior.
    *   All major Rust components (`core_engine`, `cli_client`, `gui_client`, `management_api`) utilize the `shared_utils` library for common functionalities.
    *   The `Core VPN Engine` establishes a secure tunnel to the `Internet` for the connected clients.
