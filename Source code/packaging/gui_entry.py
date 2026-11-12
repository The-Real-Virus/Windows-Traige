import sys

if len(sys.argv) > 1 and sys.argv[1] == "--elevated-event-worker":
    from windows_traige.elevation import worker_main

    raise SystemExit(worker_main(sys.argv[2:]))

from windows_traige.gui import main

raise SystemExit(main())
