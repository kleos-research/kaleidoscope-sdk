"""Strict, unpublished clients for Kaleidoscope's v1 launch descriptor."""

from .acquisition import ControllerTurn, refused_batch_items
from .descriptor import (
    EXPECTED_TOOLS,
    LaunchDescriptor,
    load_launch_descriptor,
    read_launch_descriptor,
    safe_bootstrap_environment,
)
from .entitlement import (
    ENTITLEMENT_ENV_KEYS,
    GateStatus,
    classify_refusal,
    entitlement_preflight,
    gate_status,
)
from .errors import (
    ChildProcessError,
    EntitlementError,
    DeadlineExceededError,
    DescriptorError,
    DuplicateSearchError,
    IntegrationError,
    ManagerCommandError,
    NativeRefusalError,
    OutputLimitError,
    ProtocolError,
    ToolRefusalError,
)
from .distribution import (
    InstalledPayloadPaths,
    InvalidPlatformPackageError,
    MissingPlatformPackageError,
    NATIVE_PACKAGE_TARGETS,
    UnsupportedPlatformError,
    installed_engine_path,
    installed_manager_path,
    installed_payload_paths,
    selected_native_module,
)
from .manager import (
    ACCOUNT_ENVIRONMENT_KEYS,
    AccountStatus,
    ManagerAccountClient,
    ManagerAccountCommand,
)
from .native import (
    Controller,
    Operator,
    Profile,
    load_profile,
    mcp_stdio_config,
    resolve_binary,
    resolve_manager,
)
from .session import PersistentKaleidoscopeSession
from .tool_definition import ToolDefinition
from .tools import KaleidoscopeMemory

__all__ = [
    "EXPECTED_TOOLS",
    "KaleidoscopeMemory",
    "ToolDefinition",
    "ChildProcessError",
    "EntitlementError",
    "GateStatus",
    "ENTITLEMENT_ENV_KEYS",
    "classify_refusal",
    "entitlement_preflight",
    "gate_status",
    "Controller",
    "ControllerTurn",
    "DeadlineExceededError",
    "DescriptorError",
    "DuplicateSearchError",
    "IntegrationError",
    "InstalledPayloadPaths",
    "InvalidPlatformPackageError",
    "LaunchDescriptor",
    "ManagerAccountClient",
    "ManagerAccountCommand",
    "ManagerCommandError",
    "MissingPlatformPackageError",
    "NativeRefusalError",
    "Operator",
    "OutputLimitError",
    "Profile",
    "ProtocolError",
    "PersistentKaleidoscopeSession",
    "ToolRefusalError",
    "UnsupportedPlatformError",
    "AccountStatus",
    "ACCOUNT_ENVIRONMENT_KEYS",
    "load_launch_descriptor",
    "load_profile",
    "mcp_stdio_config",
    "read_launch_descriptor",
    "refused_batch_items",
    "resolve_binary",
    "resolve_manager",
    "installed_engine_path",
    "installed_manager_path",
    "installed_payload_paths",
    "selected_native_module",
    "NATIVE_PACKAGE_TARGETS",
    "safe_bootstrap_environment",
]
