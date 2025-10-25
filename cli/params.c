#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <net/if.h>

#include "params.h"

static bool option_requires_value(enum option_type type)
{
	return type == OPT_STRING || type == OPT_STRING_MULTI ||
	       type == OPT_IFNAME || type == OPT_ENUM;
}

static struct prog_option *find_option_by_name(struct prog_option *options,
						       const char *name)
{
	struct prog_option *opt;

	if (!options || !name)
		return NULL;

	for (opt = options; opt->type != OPT_NONE; opt++) {
		if (opt->name && !strcmp(opt->name, name))
			return opt;
	}

	return NULL;
}

static struct prog_option *find_option_by_short(struct prog_option *options,
						        char short_opt)
{
	struct prog_option *opt;

	if (!options || !short_opt)
		return NULL;

	for (opt = options; opt->type != OPT_NONE; opt++) {
		if (opt->short_opt == short_opt)
			return opt;
	}

	return NULL;
}

static struct prog_option *next_positional_option(struct prog_option *options)
{
	struct prog_option *opt;

	if (!options)
		return NULL;

	for (opt = options; opt->type != OPT_NONE; opt++) {
		if (opt->positional && opt->num_set == 0)
			return opt;
	}

	return NULL;
}

static const struct enum_val *find_enum_value(const struct enum_val *vals,
                         const char *name)
{
    const struct enum_val *val;

    if (!vals || !name)
        return NULL;

    for (val = vals; val->name; val++) {
        if (!strcmp(val->name, name))
            return val;
    }

    return NULL;
}

static int set_option_value(struct prog_option *opt, void *cfg,
                 const char *value)
{
	char *field;

	if (!opt || !cfg)
		return -EINVAL;

	field = (char *)cfg + opt->cfg_offset;

	switch (opt->type) {
	case OPT_BOOL:
		if (opt->cfg_size >= sizeof(bool))
			*(bool *)field = true;
		break;
	case OPT_STRING:
		if (!value)
			return -EINVAL;
		*(const char **)field = value;
		break;
	case OPT_STRING_MULTI: {
		struct string_list *list = (struct string_list *)field;
		const char **items;
		size_t new_cap;

		if (!value || !list)
			return -EINVAL;

		if (list->count == list->capacity) {
			new_cap = list->capacity ? list->capacity * 2 : 4;
			items = realloc(list->items, new_cap * sizeof(*items));
			if (!items)
				return -ENOMEM;
			list->items = items;
			list->capacity = new_cap;
		}
		list->items[list->count++] = value;
		break;
	}
    case OPT_ENUM: {
        const struct enum_val *vals = opt->typearg;
        const struct enum_val *entry;

        if (!value || !vals)
            return -EINVAL;
        entry = find_enum_value(vals, value);
        if (!entry)
            return -EINVAL;
        if (opt->cfg_size < sizeof(entry->value))
            return -EINVAL;
        *(unsigned int *)field = entry->value;
        break;
    }
	case OPT_IFNAME: {
		struct iface *iface = (struct iface *)field;
		int ifindex;

		if (!value)
			return -EINVAL;
		ifindex = if_nametoindex(value);
		if (!ifindex)
			return -EINVAL;
		iface->ifname = value;
		iface->ifindex = ifindex;
		break;
	}
	case OPT_NONE:
	default:
		return -EINVAL;
	}

	opt->num_set++;
	return 0;
}

static void reset_options(struct prog_option *options)
{
	struct prog_option *opt;

	if (!options)
		return;

	for (opt = options; opt->type != OPT_NONE; opt++)
		opt->num_set = 0;
}

void usage(const char *prog_name, const char *doc,
       const struct prog_option *options, bool full)
{
    const struct prog_option *opt;

	if (!prog_name)
		prog_name = "xdpble";

	printf("\nUsage: %s", prog_name);
	if (options) {
		for (opt = options; opt->type != OPT_NONE; opt++) {
			if (!opt->positional)
				continue;
			printf(" %s", opt->metavar ? opt->metavar : opt->name);
		}
	}
	printf("\n");

	if (!full) {
		printf("Use --help (or -h) to see full option list.\n");
		return;
	}

	if (doc && doc[0])
		printf("\n %s\n\n", doc);

	printf("Options:\n");
	if (options) {
		for (opt = options; opt->type != OPT_NONE; opt++) {
			if (opt->positional)
				continue;
            printf("  ");
            if (opt->short_opt)
                printf("-%c, ", opt->short_opt);
            else
                printf("    ");
            printf("--%s", opt->name);
            if (option_requires_value(opt->type))
                printf(" %s", opt->metavar ? opt->metavar : "<value>");
            if (opt->help)
                printf("\t%s", opt->help);
            if (opt->type == OPT_ENUM && opt->typearg) {
                const struct enum_val *vals = opt->typearg;
                bool first = true;

                printf(" (valid: ");
                for (; vals && vals->name; vals++) {
                    if (!first)
                        printf(", ");
                    printf("%s", vals->name);
                    first = false;
                }
                printf(")");
            }
            printf("\n");
        }
	}
	printf("  -h, --help\tShow this help\n\n");
}

int parse_cmdline_args(int argc, char **argv, struct prog_option *options,
	       void *cfg, size_t cfg_capacity, size_t cfg_struct_size,
	       const char *prog_name, const char *usage_cmd, const char *doc,
	       const void *defaults)
{
	int i = 1;

	if (cfg && cfg_capacity)
		memset(cfg, 0, cfg_capacity);

	if (cfg && defaults && cfg_struct_size)
		memcpy(cfg, defaults, cfg_struct_size);

	reset_options(options);

	while (i < argc) {
		const char *arg = argv[i];
		struct prog_option *opt = NULL;
		const char *value = NULL;
		int err;

		if (!arg)
			return -EINVAL;

		if (!strcmp(arg, "--help") || !strcmp(arg, "-h")) {
			usage(usage_cmd ? usage_cmd : prog_name, doc, options, true);
			return 1;
		}

		if (arg[0] == '-' && arg[1] != '\0') {
			if (arg[1] == '-') {
				const char *name = arg + 2;

				if (*name == '\0') {
					fprintf(stderr, "Unknown option: %s\n", arg);
					return -EINVAL;
				}

				opt = find_option_by_name(options, name);
				if (!opt) {
					fprintf(stderr, "Unknown option: --%s\n", name);
					return -EINVAL;
				}

				if (option_requires_value(opt->type)) {
					if (i + 1 >= argc) {
						fprintf(stderr,
							"Option --%s requires a value\n",
							opt->name);
						return -EINVAL;
					}
					i++;
					value = argv[i];
				}
			} else {
				opt = find_option_by_short(options, arg[1]);
				if (!opt) {
					fprintf(stderr, "Unknown option: -%c\n", arg[1]);
					return -EINVAL;
				}
				if (option_requires_value(opt->type)) {
					if (i + 1 >= argc) {
						fprintf(stderr,
							"Option -%c requires a value\n",
							opt->short_opt);
						return -EINVAL;
					}
					i++;
					value = argv[i];
				}
			}

			err = set_option_value(opt, cfg, value);
			if (err) {
				fprintf(stderr, "Invalid value for --%s\n", opt->name);
				return err;
			}
			i++;
			continue;
		}

		/* Positional argument */
		opt = next_positional_option(options);
		if (!opt) {
			fprintf(stderr, "Unexpected argument: %s\n", arg);
			return -EINVAL;
		}

		err = set_option_value(opt, cfg, arg);
		if (err) {
			fprintf(stderr, "Invalid value for %s\n",
				opt->metavar ? opt->metavar : opt->name);
			return err;
		}

		i++;
	}

	/* Validate required options */
	if (options) {
		struct prog_option *opt;

		for (opt = options; opt->type != OPT_NONE; opt++) {
			if (opt->required && opt->num_set == 0) {
				fprintf(stderr, "Missing required option %s\n",
					opt->name);
				usage(usage_cmd ? usage_cmd : prog_name, doc, options, true);
				return -EINVAL;
			}

			if (opt->positional && opt->required && opt->num_set == 0) {
				fprintf(stderr, "Missing required argument %s\n",
					opt->metavar ? opt->metavar : opt->name);
				usage(usage_cmd ? usage_cmd : prog_name, doc, options, true);
				return -EINVAL;
			}
		}
	}

	return 0;
}

static const struct prog_command *find_command(const char *name,
					      const struct prog_command *cmds)
{
	const struct prog_command *cmd;

	if (!name || !cmds)
		return NULL;

	for (cmd = cmds; cmd->name; cmd++) {
		if (!strcmp(cmd->name, name))
			return cmd;
	}

	return NULL;
}

int dispatch_commands(const char *argv0, int argc, char **argv,
		      const struct prog_command *cmds, size_t cfg_size,
		      const char *prog_name)
{
	const struct prog_command *cmd;
	void *cfg = NULL;
	char usage_buf[128];
	int err;

	if (!argv0 || !cmds)
		return EXIT_FAILURE;

	cmd = find_command(argv0, cmds);
	if (!cmd) {
		fprintf(stderr, "Unknown command: %s\n", argv0);
		fprintf(stderr, "Available commands:\n");
		for (cmd = cmds; cmd->name; cmd++)
			fprintf(stderr, "  %s\n", cmd->name);
		return EXIT_FAILURE;
	}

	if (cmd->no_cfg)
		return cmd->func(NULL, NULL);

	cfg = calloc(1, cfg_size);
	if (!cfg) {
		fprintf(stderr, "Failed to allocate command context\n");
		return EXIT_FAILURE;
	}

	snprintf(usage_buf, sizeof(usage_buf), "%s %s",
		 prog_name ? prog_name : "xdpble", cmd->name);

	err = parse_cmdline_args(argc, argv, cmd->options, cfg, cfg_size,
		      cmd->cfg_size, prog_name, usage_buf, cmd->doc,
		      cmd->default_cfg);
	if (err == 1) {
		free(cfg);
		return EXIT_SUCCESS;
	}
	if (err) {
		free(cfg);
		return EXIT_FAILURE;
	}

	err = cmd->func(cfg, NULL);
	free(cfg);
	return err;
}
