--
-- SPDX-License-Identifier: BSD-2-Clause
--
-- Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
--

--
-- snl(3) parser generator.
--
-- Reads the snl: statements of a binding module (freebsd-netlink-snl)
-- against the netlink model of the protocol modules it imports, and
-- renders the C declarations consumed by <netlink/netlink_snl.h>: for
-- every parser an output structure, the sorted attribute table, the
-- fixed header field table and the SNL_DECLARE_*PARSER() tying them
-- together.
--

local model = require("lib.model")
local schema = require("lib.schema")
local yang = require("lib.yang")

local snl = {}

local fail = schema.fail
local cLower = model.cLower
local where = yang.where

-- Attribute types with a fixed C representation and snl(3) getter.
local scalars = {
	["u8"] = {ctype = "uint8_t", cb = "snl_attr_get_uint8"},
	["u16"] = {ctype = "uint16_t", cb = "snl_attr_get_uint16"},
	["u32"] = {ctype = "uint32_t", cb = "snl_attr_get_uint32"},
	["u64"] = {ctype = "uint64_t", cb = "snl_attr_get_uint64"},
	["s8"] = {ctype = "int8_t", cb = "snl_attr_get_int8"},
	["s16"] = {ctype = "int16_t", cb = "snl_attr_get_int16"},
	["s32"] = {ctype = "int32_t", cb = "snl_attr_get_int32"},
	["s64"] = {ctype = "int64_t", cb = "snl_attr_get_int64"},
	["bool"] = {ctype = "bool", cb = "snl_attr_get_bool"},
	["flag"] = {ctype = "uint8_t", cb = "snl_attr_get_flag"},
	["string"] = {ctype = "char *", cb = "snl_attr_dup_string"},
	["bitset"] = {ctype = "struct snl_attr_bitset",
	    cb = "snl_attr_get_bitset_c"},
}

-- Home of snl_attr_get_ip() and finalize_sockaddr().
local route_header = "netlink/netlink_snl_route.h"

-- Binary attributes with a meaning given by their typedef.
local hints = {
	["ipv4-or-v6"] = {ctype = "struct sockaddr *",
	    cb = "snl_attr_get_ip", include = route_header},
	["via"] = {ctype = "struct sockaddr *", cb = "snl_attr_get_ipvia",
	    include = route_header},
	["in_addr"] = {ctype = "struct in_addr",
	    cb = "snl_attr_get_in_addr", include = route_header},
	["in6_addr"] = {ctype = "struct in6_addr",
	    cb = "snl_attr_get_in6_addr", include = route_header},
	["time_t"] = {ctype = "time_t", cb = "snl_attr_get_time_t"},
}

-- Getters for fixed header fields, by field size.
local field_getters = {
	[1] = "snl_field_get_uint8",
	[2] = "snl_field_get_uint16",
	[4] = "snl_field_get_uint32",
}

--
-- Text helpers.
--

-- Display width of a line, tabs being 8 columns wide.
local function width(s)
	local col = 0

	for i = 1, #s do
		if s:byte(i) == 9 then
			col = col - col % 8 + 8
		else
			col = col + 1
		end
	end
	return col
end

-- Greedily pack space-separated tokens into lines of at most 80 columns.
local function fill(prefix, tokens, cont)
	local lines = {}
	local line = prefix .. tokens[1]

	for i = 2, #tokens do
		if width(line .. " " .. tokens[i]) > 80 then
			lines[#lines + 1] = line
			line = cont .. tokens[i]
		else
			line = line .. " " .. tokens[i]
		end
	end
	lines[#lines + 1] = line
	return lines
end

-- Word-wrap text into the body lines of a block comment.
local function wrapComment(text)
	local lines = {}
	local line = " *"

	for word in text:gmatch("%S+") do
		if #line + 1 + #word > 79 and line ~= " *" then
			lines[#lines + 1] = line
			line = " *"
		end
		line = line .. " " .. word
	end
	if line ~= " *" then
		lines[#lines + 1] = line
	end
	return lines
end

-- Strip the indentation a block of code has in the module.
local function dedent(code)
	local lines = {}
	local common

	for l in (code .. "\n"):gmatch("(.-)\n") do
		lines[#lines + 1] = (l:gsub("%s+$", ""))
	end
	while #lines > 0 and lines[1] == "" do
		table.remove(lines, 1)
	end
	while #lines > 0 and lines[#lines] == "" do
		table.remove(lines)
	end
	for _, l in ipairs(lines) do
		if l ~= "" then
			local ws = l:match("^[ \t]*")

			if common == nil then
				common = ws
			else
				local i = 1

				while i <= #common and i <= #ws and
				    common:sub(i, i) == ws:sub(i, i) do
					i = i + 1
				end
				common = common:sub(1, i - 1)
			end
		end
	end
	common = common or ""
	for i, l in ipairs(lines) do
		if l ~= "" then
			lines[i] = l:sub(#common + 1)
		end
	end
	return table.concat(lines, "\n")
end

-- "_vf_parser" -> "vf", "snl_rtm_link_parser_simple" -> "rtm_link_simple"
local function parserId(name)
	local id = name:gsub("^_+", ""):gsub("^snl_", "")

	id = id:gsub("_parser", "", 1)
	return id
end

--
-- Reading a binding module into the tables the builder works on.
--

local function checkIdent(stmt, what)
	if stmt.arg == nil or stmt.arg:match("^[%a_][%w_]*$") == nil then
		fail(where(stmt), "%s: expected a C identifier, got '%s'",
		    what, tostring(stmt.arg))
	end
	return stmt.arg
end

local function needArg(stmt)
	if stmt.arg == nil then
		fail(where(stmt), "%s needs an argument", stmt.kw)
	end
	return stmt.arg
end

local function noArg(stmt)
	if stmt.arg ~= nil then
		fail(where(stmt), "%s takes no argument", stmt.kw)
	end
	return true
end

-- The options an attribute reference or a member may carry.
local function readAttrOpts(mod, stmt, into)
	for _, s in ipairs(stmt.subs) do
		local e = mod:ext(s)

		if e == "snl:cb" then
			into["cb"] = checkIdent(s, e)
		elseif e == "snl:arg" then
			into["arg"] = needArg(s)
		elseif e == "snl:arg-u32" then
			into["arg-u32"] = needArg(s)
		elseif e == "snl:use-parser" then
			into["parser"] = checkIdent(s, e)
		elseif e == "snl:present" then
			into["present"] = needArg(s)
		elseif e == "snl:store" then
			into["member"] = needArg(s)
		elseif e == "snl:doc" then
			into["doc"] = needArg(s)
		elseif e ~= nil then
			fail(where(s), "'%s' is not allowed in %s", e, stmt.kw)
		elseif s.prefix == nil and s.kw ~= "description" then
			fail(where(s), "'%s' is not allowed in %s", s.kw,
			    stmt.kw)
		end
	end
end

local function readMember(mod, stmt)
	local m = {name = checkIdent(stmt, "snl:member")}
	local refs = {}

	for _, s in ipairs(stmt.subs) do
		local e = mod:ext(s)

		if e == "snl:attr" then
			local ref = {["name"] = needArg(s)}

			readAttrOpts(mod, s, ref)
			if ref["present"] ~= nil or ref["member"] ~= nil then
				fail(where(s), "'present' and 'store' belong " ..
				    "to the member")
			end
			refs[#refs + 1] = ref
		elseif e == "snl:type" then
			m["type"] = needArg(s)
		elseif e == "snl:field" then
			m["field"] = needArg(s)
		elseif e == "snl:presence-mask" then
			m["presence-mask"] = noArg(s)
		elseif e == "snl:tag" then
			m["tag"] = checkIdent(s, e)
		elseif e == "snl:tag-value" then
			m["tag-value"] = needArg(s)
		elseif e == "snl:required" then
			m["required"] = noArg(s)
		elseif e == "snl:scope-id" then
			m["scope-id"] = needArg(s)
		elseif e == "snl:cb" or e == "snl:arg" or e == "snl:arg-u32"
		    or e == "snl:use-parser" or e == "snl:present" or
		    e == "snl:doc" then
			readAttrOpts(mod, {subs = {s}, kw = stmt.kw}, m)
		elseif e ~= nil or s.prefix == nil then
			fail(where(s), "'%s' is not allowed in snl:member",
			    s.kw)
		end
	end
	if #refs > 0 then
		m["attr"] = refs
	end
	return m
end

local function readParser(mod, stmt)
	local yp = {
		name = checkIdent(stmt, "snl:parser"),
		members = {},
		attrs = {},
		nests = {},
		where = where(stmt),
	}

	for _, s in ipairs(stmt.subs) do
		local e = mod:ext(s)

		if e == "snl:doc" then
			yp["doc"] = needArg(s)
		elseif e == "snl:grouping" then
			yp["grouping"] = mod:groupingOf(needArg(s), s)
		elseif e == "snl:struct" then
			yp["struct"] = checkIdent(s, e)
		elseif e == "snl:out-size" then
			yp["out-size"] = needArg(s)
		elseif e == "snl:nest" then
			local path = needArg(s)
			local name = mod:getExt(s, "snl:name")

			if name == nil then
				fail(where(s), "snl:nest needs an snl:name")
			end
			yp.nests[path] = checkIdent(name, "snl:name")
		elseif e == "snl:member" then
			yp.members[#yp.members + 1] = readMember(mod, s)
		elseif e == "snl:attr" then
			local a = {["attr"] = needArg(s)}

			readAttrOpts(mod, s, a)
			yp.attrs[#yp.attrs + 1] = a
		elseif e == "snl:code" then
			yp["code"] = dedent(needArg(s))
		elseif e == "snl:post" then
			yp["post"] = checkIdent(s, e)
		elseif e ~= nil or (s.prefix == nil and
		    s.kw ~= "description") then
			fail(where(s), "'%s' is not allowed in snl:parser",
			    s.kw)
		end
	end
	if yp["grouping"] == nil then
		fail(yp.where, "parser '%s' has no snl:grouping", yp.name)
	end
	return yp
end

-- Read the snl: statements of a loaded binding module.
function snl.readBinding(mod)
	local b = {
		module = mod,
		basename = mod.basename,
		license = mod.license,
		doc = mod.doc,
		includes = {},
		code = {},
		parsers = {},
	}

	for _, s in ipairs(mod.stmt.subs) do
		local e = mod:ext(s)

		if e == "snl:include" then
			b.includes[#b.includes + 1] = needArg(s)
		elseif e == "snl:code" then
			b.code[#b.code + 1] = dedent(needArg(s))
		elseif e == "snl:parser" then
			b.parsers[#b.parsers + 1] = readParser(mod, s)
		elseif e ~= nil then
			fail(where(s), "'%s' is not allowed at the top of a " ..
			    "binding module", e)
		end
	end
	if #b.parsers == 0 then
		fail(mod.basename, "no snl:parser in the module")
	end
	return b
end

--
-- Generator state shared by all bindings of one output file.
--
local Gen = {}
Gen.__index = Gen

function snl.new()
	return setmetatable({
		bindings = {},
		parsers = {},	-- every declared parser, by C name
		ids = {},	-- identifiers derived from parser names
		structs = {},	-- output structures, by C name
		includes = {},
	}, Gen)
end

function Gen:addInclude(header)
	for _, h in ipairs(self.includes) do
		if h == header then
			return
		end
	end
	self.includes[#self.includes + 1] = header
end

function Gen:claimParser(name, parser, path)
	local id = parserId(name)

	if self.parsers[name] ~= nil then
		fail(path, "parser '%s' is already defined", name)
	end
	if self.ids[id] ~= nil then
		fail(path, "parser names '%s' and '%s' are too similar: " ..
		    "both map to the identifier '%s'", name, self.ids[id], id)
	end
	self.parsers[name] = parser
	self.ids[id] = name
	return id
end

--
-- Model building: resolve a parser description against the spec.
--

local function newNode(name, id, set)
	return {
		name = name,
		id = id,
		set = set,
		entries = {},
		children = {},
		child_by_attr = {},
	}
end

local function addEntry(node, entry, path)
	for _, e in ipairs(node.entries) do
		if e.attr == entry.attr then
			fail(path, "attribute '%s' is already parsed by " ..
			    "this parser", e.attr.name)
		end
		if e.attr.value == entry.attr.value then
			fail(path, "attributes '%s' and '%s' of set '%s' " ..
			    "have the same value %d and cannot share a parser",
			    e.attr.name, entry.attr.name, node.set.name,
			    entry.attr.value)
		end
	end
	node.entries[#node.entries + 1] = entry
end

-- Walk an attribute path ("freebsd/vf-status"), creating in-place nest nodes.
local function resolveAttr(gen, p, attr_path, path)
	local node = p.root
	local parts = {}
	local walked = ""

	if node == nil then
		fail(path, "parser '%s' has no attributes", p.name)
	end
	for part in attr_path:gmatch("[^/]+") do
		parts[#parts + 1] = part
	end
	if #parts == 0 then
		fail(path, "empty attribute name")
	end

	for i, part in ipairs(parts) do
		local attr = node.set:attr(part)

		if attr == nil then
			fail(path, "attribute '%s' is not in set '%s'", part,
			    node.set.name)
		end
		if i == #parts then
			return node, attr
		end

		walked = walked == "" and part or walked .. "/" .. part
		if attr.type ~= "nest" or attr.nested == nil or attr.multi then
			fail(path, "'%s' is not a plain nest and cannot be " ..
			    "parsed in place", walked)
		end
		local child = node.child_by_attr[part]
		if child == nil then
			local name = p.yaml.nests[walked]

			if name == nil then
				name = string.format("_%s_%s_parser", p.id,
				    cLower(walked:gsub("/", "_")))
			end
			child = newNode(name, nil, attr.nested)
			child.id = gen:claimParser(name, {name = name}, path)
			node.child_by_attr[part] = child
			node.children[#node.children + 1] = child
			addEntry(node, {
				attr = attr,
				cb = "snl_attr_get_nested",
				arg = "&" .. name,
			}, path)
			p.nest_ids[walked] = child.id
		end
		node = child
	end
end

-- Default C type, callback and argument for an attribute.
local function infer(gen, attr, parser_name, path)
	if parser_name ~= nil then
		local sub = gen.parsers[parser_name]
		local arg = "&" .. parser_name

		if sub == nil then
			fail(path, "unknown parser '%s' (parsers must be " ..
			    "defined before they are used)", parser_name)
		end
		if attr.type == "nest" and not attr.multi then
			if sub.struct == nil then
				fail(path, "parser '%s' has no struct to embed",
				    parser_name)
			end
			return "struct " .. sub.struct, "snl_attr_get_nested",
			    arg
		end
		if sub.out_size == nil then
			fail(path, "parser '%s' has no output size and " ..
			    "cannot parse array members", parser_name)
		end
		if attr.type == "nest" then
			return "struct snl_parray", "snl_attr_get_multi", arg
		elseif attr.type == "indexed-array" or
		    attr.type == "binary" then
			return "struct snl_parray", "snl_attr_get_parray", arg
		end
		fail(path, "attribute '%s' of type '%s' cannot use a parser",
		    attr.name, attr.type)
	end

	if attr.multi then
		return nil
	end
	local scalar = scalars[attr.type]
	if scalar ~= nil then
		return scalar.ctype, scalar.cb
	end
	if attr.type == "binary" then
		local hint = hints[attr.display_hint]

		if hint ~= nil then
			if hint.include ~= nil then
				gen:addInclude(hint.include)
			end
			return hint.ctype, hint.cb
		elseif attr.struct ~= nil then
			return "struct " .. attr.struct .. " *",
			    "snl_attr_dup_struct"
		end
		return "struct nlattr *", "snl_attr_dup_nla"
	elseif attr.type == "sub-message" then
		return "struct nlattr *", "snl_attr_dup_nla"
	end
	return nil
end

-- "snl_attr_get_bool" -> "get_bool"
local function cbSuffix(cb)
	return (cb:gsub("^snl_attr_", ""):gsub("^_+", ""))
end

--
-- Bind one attribute to a location in the output structure.
--   ref	attribute reference: { name, cb, arg, arg-u32, parser }
--   opts	binding options: cb, arg, arg-u32, parser, present, tag,
--		tag-value
--   target	member (path) receiving the value, if any
--   wname	name component for a generated wrapper
-- Returns the inferred C type of the value.
--
local function bindAttr(gen, p, ref, opts, target, wname, path)
	local node, attr = resolveAttr(gen, p, ref["name"], path)
	local parser_name = ref["parser"] or opts["parser"]
	local ctype, cb, arg = infer(gen, attr, parser_name, path)
	local arg_u32 = ref["arg-u32"] or opts["arg-u32"]
	local entry

	if ref["cb"] ~= nil or opts["cb"] ~= nil then
		-- What a custom callback stores is not ours to guess.
		cb = ref["cb"] or opts["cb"]
		ctype = nil
	end
	if ref["arg"] ~= nil or opts["arg"] ~= nil then
		arg = ref["arg"] or opts["arg"]
	end
	if cb == nil then
		fail(path, "no default callback for attribute '%s' of type " ..
		    "'%s'%s; set snl:cb", attr.name, attr.type,
		    attr.multi and " (repeated)" or "")
	end
	if arg ~= nil and arg_u32 ~= nil then
		fail(path, "'arg' and 'arg-u32' are mutually exclusive")
	end

	entry = {attr = attr, cb = cb, arg = arg, arg_u32 = arg_u32}

	if opts["present"] ~= nil or opts["tag"] ~= nil then
		if target == nil then
			fail(path, "'present' and 'tag' need a member to " ..
			    "store the attribute in")
		end
		if arg_u32 ~= nil then
			fail(path, "'arg-u32' cannot be combined with " ..
			    "'present' or 'tag'")
		end
		if opts["present"] ~= nil and opts["present"] == p.mask then
			-- Presence bit in the mask, set by a shared wrapper.
			if arg ~= nil then
				fail(path, "attribute '%s': callbacks " ..
				    "taking an argument cannot track " ..
				    "presence in a mask", attr.name)
			end
			if attr.value >= 64 then
				fail(path, "attribute '%s' (%d) does not " ..
				    "fit the 64-bit presence mask", attr.name,
				    attr.value)
			end
			if p.mask_cbs[cb] == nil then
				p.mask_cbs[cb] = true
				p.mask_cb_list[#p.mask_cb_list + 1] = cb
			end
			entry.cb = string.format("_snl_%s_mask_%s", p.id,
			    cbSuffix(cb))
			entry.arg = string.format("_SNL_%s_ARG(%s, %s)",
			    p.id:upper(), attr.c_name, target)
		else
			local wrapper = {
				name = string.format("_snl_%s_attr_%s", p.id,
				    wname),
				cb = cb,
				arg = arg,
				target = target,
				present = opts["present"],
				tag = opts["tag"],
				tag_value = opts["tag-value"],
			}

			p.wrappers[#p.wrappers + 1] = wrapper
			entry.cb = wrapper.name
			entry.arg = nil
		end
	elseif target ~= nil then
		entry.off = string.format("_OUT(%s)", target)
	end

	addEntry(node, entry, path)
	p.used_attrs[#p.used_attrs + 1] = attr
	return ctype
end

-- The expression telling whether a required member has been received.
local function missingExpr(p, m, ctype, refs, path)
	local present = m["present"]

	if present ~= nil and present == p.mask then
		local bits = {}

		for _, ref in ipairs(refs) do
			local _, attr = resolveAttr(nil, p, ref["name"], path)

			bits[#bits + 1] = string.format("1ULL << %s",
			    attr.c_name)
		end
		return string.format("(target->%s & (%s)) == 0", p.mask,
		    table.concat(bits, " | "))
	elseif present ~= nil then
		return "!target->" .. present
	elseif m["tag"] ~= nil then
		fail(path, "'required' cannot be combined with 'tag'; " ..
		    "check the tag member instead")
	elseif ctype:match("%*$") ~= nil then
		return string.format("target->%s == NULL", m["name"])
	end
	fail(path, "'required' needs 'present' to tell a missing " ..
	    "attribute from a zero value")
end

local function buildMember(gen, p, m, path)
	local name = m["name"]
	local refs = m["attr"] or {}
	local ctype = m["type"]
	local inferred = {}

	if p.member_by_name[name] ~= nil then
		fail(path, "duplicate member '%s'", name)
	end

	if m["presence-mask"] then
		if #refs > 0 or m["field"] ~= nil then
			fail(path, "a presence-mask member cannot have a " ..
			    "source")
		end
		ctype = ctype or "uint64_t"
	end
	if (m["tag"] ~= nil) ~= (m["tag-value"] ~= nil) then
		fail(path, "'tag' and 'tag-value' must be used together")
	end
	if m["tag"] ~= nil and m["present"] ~= nil then
		fail(path, "'tag' and 'present' are mutually exclusive")
	end
	if #refs == 0 then
		for _, key in ipairs({"cb", "arg", "arg-u32", "parser",
		    "present", "tag", "required"}) do
			if m[key] ~= nil then
				fail(path, "'%s' needs an snl:attr", key)
			end
		end
	end

	if m["field"] ~= nil then
		local hm

		if p.header == nil then
			fail(path, "'field' used in a parser without a " ..
			    "fixed header")
		end
		hm = p.header.by_name[m["field"]]
		if hm == nil then
			fail(path, "'%s' is not a member of struct '%s'",
			    m["field"], p.header.c_name)
		end
		if hm.size == nil or field_getters[hm.size] == nil then
			fail(path, "header member '%s' cannot be copied by " ..
			    "snl(3)", hm.name)
		end
		p.fields[#p.fields + 1] = {
			src = hm.c_name,
			dst = name,
			cb = field_getters[hm.size],
		}
		inferred[#inferred + 1] = string.format("%sint%d_t",
		    hm.signed and "" or "u", hm.size * 8)
	end

	for _, ref in ipairs(refs) do
		local wname = name

		if #refs > 1 then
			wname = string.format("%s_%s", name,
			    cLower(ref["name"]:gsub("/", "_")))
		end
		inferred[#inferred + 1] = bindAttr(gen, p, ref, m, name, wname,
		    path)
	end

	if ctype == nil then
		if #inferred == 0 then
			fail(path, "cannot infer the type of member '%s'; " ..
			    "set snl:type", name)
		end
		for _, t in ipairs(inferred) do
			if t ~= inferred[1] then
				fail(path, "sources of member '%s' disagree " ..
				    "on its type (%s, %s); set snl:type", name,
				    inferred[1], t)
			end
		end
		ctype = inferred[1]
	end

	if m["required"] then
		p.required[#p.required + 1] = missingExpr(p, m, ctype, refs,
		    path)
	end
	if m["scope-id"] ~= nil then
		gen:addInclude(route_header)
		p.scopes[#p.scopes + 1] = {
			member = name,
			ifindex = m["scope-id"],
		}
	end

	local member = {name = name, ctype = ctype, doc = m["doc"]}
	p.members[#p.members + 1] = member
	p.member_by_name[name] = member
end

-- Check that a member path ("iflaf_vf_status.present") starts at a member.
local function checkMemberPath(p, mpath, what, path)
	local first = mpath:match("^([%a_][%w_]*)")

	if first == nil or mpath:match("^[%a_][%w_%.]*$") == nil then
		fail(path, "'%s': '%s' is not a member path", what, mpath)
	end
	if p.member_by_name[first] == nil then
		fail(path, "'%s' refers to unknown member '%s'", what, first)
	end
end

local function buildParser(gen, binding, yp)
	local path = yp.where
	local p = {
		name = yp["name"],
		yaml = yp,
		binding = binding,
		doc = yp["doc"],
		struct = yp["struct"],
		out_size = yp["out-size"],
		code = yp["code"],
		post = yp["post"],
		members = {},
		member_by_name = {},
		fields = {},
		wrappers = {},
		mask_cbs = {},
		mask_cb_list = {},
		required = {},
		scopes = {},
		used_attrs = {},
		nest_ids = {},
	}

	p.id = gen:claimParser(p.name, p, path)
	p.header = yp.grouping.header
	p.root = newNode(p.name, p.id, yp.grouping.set)
	if p.header == nil and #yp.grouping.set.attrs == 0 then
		fail(path, "parser '%s': grouping '%s' has neither a fixed " ..
		    "header nor attributes", p.name, yp.grouping.name)
	end

	if p.struct ~= nil then
		if p.out_size ~= nil then
			fail(path, "'struct' and 'out-size' are mutually " ..
			    "exclusive")
		end
		if gen.structs[p.struct] ~= nil then
			fail(path, "struct '%s' is already generated by " ..
			    "parser '%s'", p.struct, gen.structs[p.struct])
		end
		if #yp.members == 0 then
			fail(path, "struct '%s' has no members", p.struct)
		end
		gen.structs[p.struct] = p.name
		p.out_size = string.format("sizeof(struct %s)", p.struct)
	elseif #yp.members > 0 then
		fail(path, "members need a 'struct' to live in")
	end

	-- The mask member has to be known before attributes are bound.
	for _, m in ipairs(yp.members) do
		if m["presence-mask"] then
			if p.mask ~= nil then
				fail(path, "only one presence-mask member is " ..
				    "supported")
			end
			p.mask = m["name"]
		end
	end

	for i, m in ipairs(yp.members) do
		buildMember(gen, p, m, string.format("%s: member %s", path,
		    m["name"]))
	end

	for _, a in ipairs(yp.attrs) do
		local apath = string.format("%s: attr %s", path, a["attr"])
		local wname = cLower(a["attr"]:gsub("/", "_"))

		if a["member"] ~= nil then
			if p.struct == nil then
				fail(apath, "'store' used in a parser " ..
				    "without a struct")
			end
			checkMemberPath(p, a["member"], "store", apath)
		end
		bindAttr(gen, p, {["name"] = a["attr"]}, a, a["member"], wname,
		    apath)
	end

	for _, m in ipairs(yp.members) do
		local mpath = string.format("%s: member %s", path, m["name"])

		if m["present"] ~= nil then
			checkMemberPath(p, m["present"], "present", mpath)
		end
		if m["tag"] ~= nil then
			checkMemberPath(p, m["tag"], "tag", mpath)
		end
		if m["scope-id"] ~= nil then
			checkMemberPath(p, m["scope-id"], "scope-id", mpath)
		end
	end
	for _, a in ipairs(yp.attrs) do
		if a["present"] ~= nil then
			checkMemberPath(p, a["present"], "present",
			    string.format("%s: attr %s", path, a["attr"]))
		end
	end

	for walked in pairs(yp.nests) do
		if p.nest_ids[walked] == nil then
			fail(path, "no member uses an attribute of nest '%s'",
			    walked)
		end
	end

	if #p.root.entries == 0 then
		if p.header == nil then
			fail(path, "parser '%s' does not parse anything",
			    p.name)
		end
		p.root = nil
	end

	return p
end

-- Resolve the parsers of a binding; they are emitted by Gen:render().
function Gen:addBinding(b)
	local entry = {binding = b, parsers = {}, used = {}, used_list = {},
	    modules = {}, module_list = {}}

	for _, header in ipairs(b.includes) do
		self:addInclude(header)
	end

	for _, yp in ipairs(b.parsers) do
		local p = buildParser(self, b, yp)
		local gm = yp.grouping.module

		entry.parsers[#entry.parsers + 1] = p
		if entry.modules[gm.name] == nil then
			entry.modules[gm.name] = gm
			entry.module_list[#entry.module_list + 1] = gm
			if gm:extArg(gm.stmt, "nlx:protocol") ==
			    "NETLINK_GENERIC" then
				self:addInclude("netlink/netlink_snl_generic.h")
			end
		end
	end
	-- Every attribute in a table, nests parsed in place included;
	-- listed by attribute set, in order of first use, then by value.
	local sets, nsets = {}, 0
	local function use(attr)
		if sets[attr.set] == nil then
			nsets = nsets + 1
			sets[attr.set] = nsets
		end
		if entry.used[attr.c_name] == nil then
			entry.used[attr.c_name] = attr
			entry.used_list[#entry.used_list + 1] = attr
		end
	end
	local function markNode(node)
		for _, e in ipairs(node.entries) do
			use(e.attr)
		end
		for _, child in ipairs(node.children) do
			markNode(child)
		end
	end
	for _, p in ipairs(entry.parsers) do
		if p.root ~= nil then
			markNode(p.root)
		end
		for _, attr in ipairs(p.used_attrs) do
			use(attr)
		end
	end
	table.sort(entry.used_list, function(a, b)
		if sets[a.set] ~= sets[b.set] then
			return sets[a.set] < sets[b.set]
		end
		return a.value < b.value
	end)

	self.bindings[#self.bindings + 1] = entry
end

--
-- Rendering.
--

local Out = {}
Out.__index = Out

function Out:line(fmt, ...)
	if select("#", ...) > 0 then
		self[#self + 1] = string.format(fmt, ...)
	else
		self[#self + 1] = fmt or ""
	end
end

function Out:lines(lines)
	for _, l in ipairs(lines) do
		self[#self + 1] = l
	end
end

function Out:comment(text)
	local lines = wrapComment(text)

	if #lines == 1 and #lines[1] + 4 <= 80 then
		self:line("/*%s */", lines[1]:sub(3))
	else
		self:line("/*")
		self:lines(lines)
		self:line(" */")
	end
end

-- Verbatim C from the spec, without trailing blank lines.
function Out:code(code)
	for l in (code:gsub("%s+$", "") .. "\n"):gmatch("(.-)\n") do
		self:line((l:gsub("%s+$", "")))
	end
end

local function renderStruct(out, p)
	local decls = {}
	local longest = 0

	for _, m in ipairs(p.members) do
		local base = m.ctype
		local name = m.name
		local stars, dims

		base, dims = base:match("^(.-)%s*(%[.*%])$")
		if base == nil then
			base = m.ctype
			dims = ""
		end
		stars = base:match("(%*+)$") or ""
		base = base:sub(1, #base - #stars):gsub("%s+$", "")
		decls[#decls + 1] = {
			base = base,
			name = stars .. name .. dims,
			doc = m.doc,
		}
		if #base > longest then
			longest = #base
		end
	end

	local column = longest - longest % 8 + 8

	out:line("struct %s {", p.struct)
	for _, d in ipairs(decls) do
		local tabs = (column - #d.base + 7) // 8
		local decl = string.format("\t%s%s%s;", d.base,
		    string.rep("\t", tabs), d.name)

		if d.doc == nil then
			out:line(decl)
		elseif width(decl) + 8 + #d.doc + 6 <= 80 then
			out:line("%s\t/* %s */", decl, d.doc)
		else
			out:line("\t/* %s */", d.doc)
			out:line(decl)
		end
	end
	out:line("};")
end

-- "struct foo *p = (struct foo *)target;", wrapped if needed.
local function castLines(struct, var, src)
	return fill("\t", {
		string.format("struct %s *%s =", struct, var),
		string.format("(struct %s *)%s;", struct, src),
	}, "\t    ")
end

local wrapper_args = "(struct snl_state *ss, struct nlattr *nla,"

local function renderWrappers(out, p)
	if #p.mask_cb_list > 0 then
		local id = p.id:upper()

		-- Attribute number and member offset travel in the argument.
		out:line()
		out:line("#define\t_SNL_%s_ARG(_attr, _field)\t" ..
		    "((const void *)(uintptr_t)(\t\\", id)
		out:line("\t((uint32_t)(_attr) << 16) | " ..
		    "offsetof(struct %s, _field)))", p.struct)
		out:line()
		out:line("#define\t_SNL_%s_GETTER(_name, _getter)" ..
		    "\t\t\t\t\t\\", id)
		for _, l in ipairs({
			"static inline bool",
			"_name(struct snl_state *ss, struct nlattr *nla, " ..
			    "const void *arg,",
			"    void *target)",
			"{",
			string.format("\tstruct %s *p = (struct %s *)target;",
			    p.struct, p.struct),
			"\tuintptr_t v = (uintptr_t)arg;",
			"",
			"\tif (!_getter(ss, nla, NULL, (char *)target + " ..
			    "(v & 0xffff)))",
			"\t\treturn (false);",
			string.format("\tp->%s |= 1ULL << (v >> 16);", p.mask),
			"\treturn (true);",
		}) do
			local pad = (72 - width(l) + 7) // 8

			out:line("%s%s\\", l, string.rep("\t", math.max(pad,
			    1)))
		end
		out:line("}")
		for _, cb in ipairs(p.mask_cb_list) do
			out:line("_SNL_%s_GETTER(_snl_%s_mask_%s, %s)", id,
			    p.id, cbSuffix(cb), cb)
		end
		out:line("#undef _SNL_%s_GETTER", id)
	end

	for _, w in ipairs(p.wrappers) do
		local call = {
			string.format("!%s(ss, nla, %s,", w.cb,
			    w.arg or "NULL"),
			string.format("&p->%s))", w.target),
		}

		out:line()
		out:line("static inline bool")
		out:line("%s%s", w.name, wrapper_args)
		out:line("    const void *arg __unused, void *target)")
		out:line("{")
		out:lines(castLines(p.struct, "p", "target"))
		out:line()
		if w.tag ~= nil then
			-- Tagged members are exclusive: refuse a second value.
			call[1] = string.format("if (p->%s != 0 || %s", w.tag,
			    call[1])
		else
			call[1] = "if (" .. call[1]
		end
		out:lines(fill("\t", call, "\t    "))
		out:line("\t\treturn (false);")
		if w.tag ~= nil then
			out:line("\tp->%s = %s;", w.tag, tostring(w.tag_value))
		else
			out:line("\tp->%s = true;", w.present)
		end
		out:line("\treturn (true);")
		out:line("}")
	end
end

local function renderAttrTable(out, node)
	table.sort(node.entries, function(a, b)
		return a.attr.value < b.attr.value
	end)

	out:line("static const struct snl_attr_parser _nla_p_%s[] = {", node.id)
	for _, e in ipairs(node.entries) do
		local items = {string.format(".type = %s", e.attr.c_name)}

		if e.off ~= nil then
			items[#items + 1] = ".off = " .. e.off
		end
		if e.arg ~= nil then
			items[#items + 1] = ".arg = " .. e.arg
		end
		if e.arg_u32 ~= nil then
			items[#items + 1] = ".arg_u32 = " .. tostring(e.arg_u32)
		end
		items[#items + 1] = ".cb = " .. e.cb
		for i, item in ipairs(items) do
			items[i] = item .. (i < #items and "," or " },")
		end
		items[1] = "{ " .. items[1]
		out:lines(fill("\t", items, "\t    "))
	end
	out:line("};")
end

-- Tables of nests parsed in place, innermost first.
local function renderNests(out, node)
	for _, child in ipairs(node.children) do
		renderNests(out, child)
		renderAttrTable(out, child)
		out:line("SNL_DECLARE_ATTR_PARSER(%s, _nla_p_%s);", child.name,
		    child.id)
		out:line()
	end
end

local function renderPost(out, p)
	local name = "_cb_p_" .. p.id

	if #p.required == 0 and #p.scopes == 0 then
		return p.post
	end

	out:line()
	out:line("static inline bool")
	out:line("%s(struct snl_state *ss%s, void *_target)", name,
	    p.post == nil and " __unused" or "")
	out:line("{")
	out:lines(castLines(p.struct, "target", "_target"))
	out:line()
	if #p.required > 0 then
		local tokens = {}

		for i, expr in ipairs(p.required) do
			tokens[i] = expr .. (i < #p.required and " ||" or ")")
		end
		tokens[1] = "if (" .. tokens[1]
		out:lines(fill("\t", tokens, "\t    "))
		out:line("\t\treturn (false);")
	end
	for _, s in ipairs(p.scopes) do
		out:line("\tfinalize_sockaddr(target->%s, target->%s);",
		    s.member, s.ifindex)
	end
	if p.post ~= nil then
		out:line("\treturn (%s(ss, _target));", p.post)
	else
		out:line("\treturn (true);")
	end
	out:line("}")
	return name
end

local function renderDeclare(out, macro, args)
	local tokens = {}

	for i, a in ipairs(args) do
		tokens[i] = a .. (i < #args and "," or ");")
	end
	tokens[1] = macro .. "(" .. tokens[1]
	out:lines(fill("", tokens, "    "))
end

local function renderParser(out, p)
	local np = p.root ~= nil and "_nla_p_" .. p.id or nil
	local fp = #p.fields > 0 and "_fp_p_" .. p.id or "snl_f_p_empty"
	local hdr_size, cb

	if p.doc ~= nil then
		out:comment(p.doc)
	end
	if p.struct ~= nil then
		renderStruct(out, p)
	end
	if p.code ~= nil then
		if p.struct ~= nil then
			out:line()
		end
		out:code(p.code)
	end
	renderWrappers(out, p)
	if p.struct ~= nil or p.code ~= nil then
		out:line()
	end

	if p.header ~= nil then
		hdr_size = string.format("sizeof(struct %s)", p.header.c_name)
	end
	if #p.fields > 0 then
		out:line("#define\t_IN(_field)\toffsetof(struct %s, _field)",
		    p.header.c_name)
	end
	if p.struct ~= nil then
		out:line("#define\t_OUT(_field)\toffsetof(struct %s, _field)",
		    p.struct)
	end
	if p.root ~= nil then
		renderNests(out, p.root)
		renderAttrTable(out, p.root)
	end
	if #p.fields > 0 then
		if p.root ~= nil then
			out:line()
		end
		out:line("static const struct snl_field_parser %s[] = {", fp)
		for _, f in ipairs(p.fields) do
			out:lines(fill("\t", {
				string.format("{ .off_in = _IN(%s),", f.src),
				string.format(".off_out = _OUT(%s),", f.dst),
				string.format(".cb = %s },", f.cb),
			}, "\t    "))
		end
		out:line("};")
		out:line("#undef _IN")
	end
	if p.struct ~= nil then
		out:line("#undef _OUT")
	end

	cb = renderPost(out, p)
	out:line()

	if p.header == nil then
		if p.out_size == nil and cb == nil then
			renderDeclare(out, "SNL_DECLARE_ATTR_PARSER",
			    {p.name, np})
		else
			renderDeclare(out, "SNL_DECLARE_ATTR_PARSER_EXT",
			    {p.name, p.out_size or "0", np, cb or "NULL"})
		end
	elseif p.root == nil then
		renderDeclare(out, "SNL_DECLARE_FIELD_PARSER_EXT",
		    {p.name, hdr_size, p.out_size or "0", fp, cb or "NULL"})
	else
		renderDeclare(out, "SNL_DECLARE_PARSER_EXT",
		    {p.name, hdr_size, p.out_size or "0", fp, np,
		    cb or "NULL"})
	end
end

local function renderBinding(out, entry)
	local b = entry.binding
	local names = {}

	for _, gm in ipairs(entry.module_list) do
		names[#names + 1] = gm.basename
	end
	out:line("/*")
	if b.doc ~= nil then
		out:lines(wrapComment(b.doc:match("^(.-)%.%s") or b.doc))
		out:line(" *")
	end
	out:lines(wrapComment(string.format("Generated from %s and %s.",
	    b.basename, table.concat(names, ", "))))
	out:line(" */")
	out:line()

	-- Attribute tables are searched by value: pin the values they are
	-- sorted by to the ones the compiler sees.
	for _, attr in ipairs(entry.used_list) do
		local cond = string.format("_Static_assert(%s == %d,",
		    attr.c_name, attr.value)
		local msg = string.format("\"%s\");",
		    attr.set.module.basename)

		out:lines(fill("", {cond, msg}, "    "))
	end
	if #entry.used_list > 0 then
		out:line()
	end

	for _, code in ipairs(b.code) do
		out:code(code)
		out:line()
	end

	for _, p in ipairs(entry.parsers) do
		renderParser(out, p)
		out:line()
	end
end

-- Produce the text of the generated header.
function Gen:render(guard, generator)
	local out = setmetatable({}, Out)
	local license

	for _, entry in ipairs(self.bindings) do
		local l = entry.binding.license

		if l == nil then
			fail(entry.binding.basename, "module has no " ..
			    "SPDX-License-Identifier")
		end
		if license ~= nil and license ~= l then
			fail(entry.binding.basename, "license '%s' differs " ..
			    "from the '%s' of the other modules", l, license)
		end
		license = l
	end

	out:line("/*-")
	out:line(" * SPDX-License-Identifier: %s", license)
	out:line(" *")
	out:line(" * DO NOT EDIT-- this file is automatically @" ..
	    "generated.")
	out:line(" *")
	out:line(" * Generated by %s from:", generator or "yanl")
	for _, entry in ipairs(self.bindings) do
		out:line(" *\t%s", entry.binding.basename)
	end
	out:line(" */")
	out:line("#ifndef\t%s", guard)
	out:line("#define\t%s", guard)
	out:line()
	out:line("#include <netlink/netlink_snl.h>")
	for _, header in ipairs(self.includes) do
		out:line("#include <%s>", header)
	end
	out:line()

	for _, entry in ipairs(self.bindings) do
		renderBinding(out, entry)
	end

	out:line("#endif")
	return table.concat(out, "\n") .. "\n"
end

return snl
