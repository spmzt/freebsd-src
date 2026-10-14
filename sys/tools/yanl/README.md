# yanl: YANG netlink

`yanl.lua` generates C headers of snl(3) message parsers, such as
`sys/netlink/netlink_snl_route_parsers.h`, from the YANG modules that
describe FreeBSD's netlink(4) protocols
(<https://github.com/spmzt/yang>, `standard/freebsd` of the YangModels
repository).  It is to those modules what `ynl_gen_c.py` is to the
netlink YAML specs of Linux, and the successor of the YAML-based
generator of the `snlgen` branch.

The script runs under flua and needs nothing outside of the base
system: the YANG parser is its own.  The modules are in
`sys/netlink/specs`; generated headers are committed to the tree, so
the generator is not part of the build.

## Usage

    /usr/libexec/flua sys/tools/yanl/yanl.lua [-p dir] ... [-g guard] [-o output] binding ...

* `-p dir` adds a directory to the search path for modules, by name
  (`name.yang`, or the newest `name@revision.yang`).  The directory of
  every module given by path is added as well.
* `-o output` writes the header to `output` instead of standard
  output.
* `-g guard` is the include guard; the default derives from the output
  file's name.

The arguments are binding modules, by name or path; they are emitted
in order, and a parser may only use the parsers of the bindings before
it.  To regenerate the headers kept in `sys/netlink` after editing a
module in `sys/netlink/specs`:

    make -C sys/netlink snl

## How it reads YANG

A protocol module (`freebsd-rtnetlink-link`, `freebsd-genetlink-carp`
...) says what is on the wire through the statements of
`freebsd-netlink-extensions`: `nlx:attr` gives an attribute's type
number, `nlx:name-prefix` and `nlx:c-name` its C name,
`nlx:fixed-header` and `nlx:struct` the structures, `nlx:width` the
size of an enumeration or bits leaf, `nlx:array` a container of
entries.  The YANG type of a leaf is its wire type; the typedefs of
`freebsd-netlink-types` tell the generator which binary attributes are
addresses.  The description of `freebsd-netlink-extensions` is the
complete reading rule.

A binding module (`freebsd-rtnetlink-link-snl`) imports a protocol
module and says what to generate from it, with the statements of
`freebsd-netlink-snl`:

    snl:parser snl_rtm_neigh_parser {
      snl:doc "RTM_<NEW|DEL|GET>NEIGH message parser";
      snl:struct snl_parsed_neigh;
      snl:grouping rtneigh:neigh-message;
      snl:nest freebsd {
        snl:name _neigh_fbsd_parser;
      }
      snl:member ndm_family {
        snl:field ndm-family;
      }
      snl:member nda_ifindex {
        snl:type uint32_t;
        snl:field ndm-ifindex;
        snl:attr ifindex;
      }
      snl:member nda_dst {
        snl:attr dst;
        snl:scope-id nda_ifindex;
      }
      snl:member ndaf_next_ts {
        snl:attr freebsd/next-state-ts;
      }
    }

Each `snl:parser` declares one `struct snl_hdr_parser`.  Its
`snl:grouping` is the grouping of the protocol module it parses: a
message (a grouping with `nlx:fixed-header`), or an attribute set.

| Statement | Meaning |
|-----------|---------|
| `snl:doc` | Comment for the generated code. |
| `snl:struct` | Name of the output structure to generate from the members. |
| `snl:out-size` | Size of the output for parsers that do not fill a structure, e.g. `sizeof(char[IFNAMSIZ])`.  Mutually exclusive with `snl:struct`. |
| `snl:grouping` | The grouping parsed, with its prefix. |
| `snl:member` | Members of the output structure, in order. |
| `snl:attr` | Attributes to parse that do not add a member of their own. |
| `snl:nest` | C name (`snl:name`) for the parser of a nest parsed in place, by attribute path.  The default is `_<parser>_<path>_parser`. |
| `snl:code` | C code emitted verbatim after the structure and before the tables; at the top of the module, before the parsers. |
| `snl:post` | Function of type `snl_parse_post_f` to finish and validate the output. |

A member has a name and takes its value from the fixed header
(`snl:field`), from one or more attributes (`snl:attr`), from both, or
from nowhere:

| Statement | Meaning |
|-----------|---------|
| `snl:doc` | Comment for the member. |
| `snl:type` | C type.  Defaults to the type implied by the source of the value; mandatory if there is none or a custom callback is used. |
| `snl:field` | Leaf of the fixed header to copy. |
| `snl:attr` | Attribute stored in the member, by path; may carry its own `snl:cb`, `snl:arg`, `snl:arg-u32` or `snl:use-parser`.  Repeatable. |
| `snl:cb` | Attribute callback to use instead of the default one. |
| `snl:arg`, `snl:arg-u32` | C expression passed to the callback. |
| `snl:use-parser` | Parser of the contents of a nest or an array. |
| `snl:present` | Member (path) recording that the attribute was received: a `bool`, or the presence mask. |
| `snl:presence-mask` | The member is a `uint64_t` with one bit per received attribute, indexed by attribute value. |
| `snl:tag`, `snl:tag-value` | Member to set to the value when the attribute is received.  Members sharing a tag are exclusive: a second one fails the parser. |
| `snl:required` | Fail the parser if the attribute is missing.  Needs a pointer type or `snl:present`. |
| `snl:scope-id` | Member holding the interface index used to fill in the scope of a link-local IPv6 address. |

An attribute path with slashes, such as `freebsd/caps`, reaches into
a nest, whose attributes are then stored in the same structure as the
top level ones through a second attribute table.  A parser-level
`snl:attr` has the path, optionally `snl:store` (a member path) and
the options above; it serves attributes stored at offset zero of a
plain output and attributes stored inside an embedded structure.

### Default types and callbacks

| Attribute | C type | Callback |
|-----------|--------|----------|
| `uint8` ... `uint64` | `uintN_t` | `snl_attr_get_uintN` |
| `int8` ... `int64` | `intN_t` | `snl_attr_get_intN` |
| enumeration, bits | `uintN_t` of `nlx:width` | `snl_attr_get_uintN` |
| `boolean` | `bool` | `snl_attr_get_bool` |
| `empty` | `uint8_t` | `snl_attr_get_flag` |
| `string` | `char *` | `snl_attr_dup_string` |
| `nlt:ip-address` | `struct sockaddr *` | `snl_attr_get_ip` |
| `nlt:rtvia` | `struct sockaddr *` | `snl_attr_get_ipvia` |
| `nlt:in-addr`, `nlt:in6-addr` | `struct in_addr`, `struct in6_addr` | `snl_attr_get_in_addr`, `_in6_addr` |
| `nlt:time-t` | `time_t` | `snl_attr_get_time_t` |
| container using `nl:bitset` | `struct snl_attr_bitset` | `snl_attr_get_bitset_c` |
| container or list with `nlx:struct` | `struct foo *` | `snl_attr_dup_struct` |
| other `binary`, a choice with `nlx:attr` | `struct nlattr *` | `snl_attr_dup_nla` |
| container (nest) with `snl:use-parser` | `struct <output of the parser>` | `snl_attr_get_nested` |
| list (repeated nest) with `snl:use-parser` | `struct snl_parray` | `snl_attr_get_multi` |
| list or leaf-list with `nlx:array`, or `binary`, with `snl:use-parser` | `struct snl_parray` | `snl_attr_get_parray` |

Header fields are copied by `snl_field_get_uint8`, `16` or `32`.
Anything else needs an explicit `snl:cb`, which can be a function
provided by `snl:code`.

## Generated code

For every parser the generator emits:

* the output structure;
* the `snl:code` of the parser and the wrappers implementing
  `snl:present` and `snl:tag`;
* an attribute table per nest parsed in place and one for the parser
  itself, sorted by attribute value as snl(3) requires;
* the table of fixed header fields;
* a post-parse callback checking `snl:required` members and applying
  `snl:scope-id`;
* the `SNL_DECLARE_*PARSER()` declaration.

The attribute values of a module are not taken on trust: each
attribute that appears in a table gets a `_Static_assert()` comparing
its value in the module to the one in the uAPI headers.  A module that
goes out of sync with the headers breaks the build instead of the
binary search of the tables.

## Organization

* `yanl.lua` - command line entry point.
* `lib/yang.lua` - the YANG parser: text to statements.
* `lib/model.lua` - modules, imports, typedefs, groupings and the
  `nlx:` statements, resolved into attribute sets and structures.
* `lib/snl.lua` - the `snl:` statements resolved against the model,
  and the C rendering.
* `lib/schema.lua` - the error type the generator reports without a
  traceback.

The front-end (`yang.lua`, `model.lua`) knows nothing of snl(3); a
second back-end, emitting schema tables for a run-time translation
between netlink and YANG-CBOR, would sit beside `snl.lua`.

The YANG subset understood is what the modules use: modules with
imports, typedefs, groupings and `uses`, leaf, leaf-list, container,
list, choice, case and anydata, rpc, notification, and extension
statements.  Submodules, augment, deviation and refine are not
supported.
