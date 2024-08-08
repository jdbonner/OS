# WINDOWS
## Registry keys


## Services
  >services running at system level being changed to a different executable

### Commands
  tasklist /svc
  get-ciminstance win32_service | format-list name, pathname
