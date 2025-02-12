UDP_SERVER_PORT = 9001
WEB_SERVER_PORT = 9002
UDP_IP = "10.10.100.55"

	
SIEM_MODULE = 1
UEBA_MODULE = 2
WEB_WAF = 3
DAM = 4
SOAR = 5
	
# Length 
LEN_15=15
LEN_20=20
LEN_50=50
LEN_80=80
LEN_100=100
	
# Device Type
PC=1
SERVER=2
WS=3
FIREWALL=4
SWITCH=5
ROUTER=6
	
# MesgId 
RAW_LOG_DATA=1
EVENT_LOG_DATA=2
	
# Event Type
AuthenticationEvents=1
NetworkActivityEvents=2
SystemActivityEvents=3
ApplicationEvents=4
UserActivityEvents=5
EndpointSecurityEvents=6
DistributedDOSEvents=7
FileAndObjectAccessEvents = 8

# Event Sub Type
SuccessfulLogin=1
FailedLogin=2
AccountLockout=3
PrivilegeEscalation=4
MFA_Events=5
UnusualLoginPattern=6	
AllowedConnection=7
BlockedConnection=8
OpenPortScans=9
HighVolumeDataTransfer=10
VPNActivity=11
MalwareDetection=12
PhishingAttempt=13
SuspiciousBehaviour=14
RansomwareDetection=15
IntrusionDetectionPrevention=16
FileCreation=17
FileModification=18
FileDeletion=19
AccessDenied=20
DataExfiltration=21
UnusualDataAccess=22
ServiceStartStop=23
SystemBootReboot=24
ProcessCreationTermination=25
ConfigurationChanges=26
PatchingEvents=27
ApplicationAccess=28
DatabaseQueries=29
FailedTransactions=30
PrivilegeChanges=32
PolicyBreach=33
DataExportEvents=34
UserCreation=45
UserDeletion=46
PolicyViolations=47
IdleSessions=48
UnusualUserActivity=49
EndPointDetectionResp=50
DeviceConnection=51
DeviceMalwareEvents=52
DDoSAttackDetected=53
MitigationActions=54
EmailSecurity=55
CompromisedAccount=56
UnauthorisedSoftwareInstallation=57
UnauthorisedSoftwareRemoval=58
PasswordChange=59
Logout=60
InvalidverificationCode = 61
FileEncryption = 62
FileRead=63

#################> THRESHOLDS <######################
# Thresholds (in bytes) and time range (in seconds)

TIME_RANGE = 1  # 1 sec
PORT_SCAN_THRES = 10  # Number of attempts to trigger alert
UPLOAD_THRESHOLD = 1000000  # 1000 KB = 1MB
DOWNLOAD_THRESHOLD = 1000000 # 1000 KB
CPU_USAGE_THRESHOLD = 90  # CPU usage percentage threshold
DISK_USAGE_THRESHOLD = 90  # Disk usage percentage threshold
PACKET_COUNT_THRESHOLD = 100000  # Number of packets in TIME_RANGE to trigger DoS detection
MEMORY_USAGE_THRESHOLD = 90  # Memory usage percentage threshold



# Define unusual login hours
UNUSUAL_START_HOUR = 13  # 10 PM
UNUSUAL_END_HOUR = 18 # 6 AM

#IDLE SESSION
IDLE_TIMEOUT = 5       # Idle timeout in seconds (adjust as needed)
IDLE_CHECK_INTERVAL = 5  # Seconds between idle checks


USB_MOUNT_PATH = "/SIEM_USB_SCAN"
MALWARE_SCAN_INTERVAL = 600 # in seconds = 10 minute