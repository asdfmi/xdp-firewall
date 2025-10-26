#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "cli_shared.h"
#include "xdt.h"
#include "params.h"

const struct prog_command cmds[] = {
	DEFINE_COMMAND(attach, "Attach XDP Telemetry program to an interface"),
	DEFINE_COMMAND(detach, "Detach XDP Telemetry program from an interface"),
	DEFINE_COMMAND(add, "Add IPv4 telemetry rule"),
	DEFINE_COMMAND(list, "List telemetry rules"),
	DEFINE_COMMAND(log, "Stream telemetry events"),
	DEFINE_COMMAND(help, "Show help message"),
	END_COMMANDS
};

union all_opts {
	struct attachopt attach;
	struct detachopt detach;
	struct addopt add;
	struct listopt list;
	struct logopt log;
	struct helpopt help;
};

int main(int argc, char **argv)
{
	if (argc > 1)
		return dispatch_commands(argv[1], argc - 1, argv + 1, cmds,
				       sizeof(union all_opts), PROG_NAME);

	return do_help(NULL, NULL);
}
