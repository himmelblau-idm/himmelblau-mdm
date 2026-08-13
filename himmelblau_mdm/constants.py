GRAPH_AUDIENCES = frozenset(
    {"00000003-0000-0000-c000-000000000000", "https://graph.microsoft.com"}
)
ENROLLMENT_AUDIENCES = frozenset({"d4ebce55-015a-49b5-a083-c84d1797ae8c"})
CHECKIN_AUDIENCES = frozenset({"0000000a-0000-0000-c000-000000000000"})
IWSERVICE_AUDIENCES = frozenset({"b8066b99-6e67-41be-abfa-75db1a2c8809"})
LINUX_PORTAL_CLIENT_ID = "b743a22d-6705-4147-8670-d92fa515ee2b"
INTUNE_PORTAL_APP_ID = "0000000a-0000-0000-c000-000000000000"

EXPECTED_SERVICE_PATHS = {
    "LinuxEnrollmentService": "/LinuxMDM/LinuxEnrollmentService",
    "LinuxDeviceCheckinService": "/LinuxMDM/LinuxDeviceCheckinService",
    "IWService": "/IWService/",
}

FAILURE_STATES = frozenset({"noncompliant", "error", "unknown"})
