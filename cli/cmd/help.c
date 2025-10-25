#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "cli_shared.h"
#include "xdp-labeling.h"
#include "params.h"

/* forward declaration provided by main compilation unit */
extern const struct prog_command cmds[];

const struct helpopt defaults_help = {};

struct prog_option help_options[] = {
	DEFINE_OPTION("command", OPT_STRING, struct helpopt, command,
		.positional = true,
		.metavar = "[command]",
		.help = "Command to show help for"),
	END_OPTIONS
};

static void print_global_usage(void)
{
	const struct prog_command *cmd;

	printf("Usage: %s COMMAND [options]\n\n", PROG_NAME);
	printf("COMMAND can be one of:\n");
	for (cmd = cmds; cmd->name; cmd++)
		printf("  %-10s %s\n", cmd->name,
		       cmd->doc ? cmd->doc : "");
	printf("\nUse '%s COMMAND --help' to see options for each command\n",
	       PROG_NAME);
}

static int show_command_help(const char *command_name)
{
	const struct prog_command *cmd;
	char usage_buf[128];

	for (cmd = cmds; cmd->name; cmd++) {
		if (strcmp(cmd->name, command_name))
			continue;

		snprintf(usage_buf, sizeof(usage_buf), "%s %s", PROG_NAME,
			 cmd->name);
		usage(usage_buf, cmd->doc, cmd->options, true);
		return EXIT_SUCCESS;
	}

	return EXIT_FAILURE;
}

int do_help(const void *cfg, __unused const char *pin_root_path)
{
	const struct helpopt *opt = cfg;

	if (opt && opt->command) {
		if (show_command_help(opt->command) == EXIT_SUCCESS)
			return EXIT_SUCCESS;
		fprintf(stderr, "help: unknown command: %s\n", opt->command);
		return EXIT_FAILURE;
	}

	print_global_usage();
	return EXIT_SUCCESS;
}
