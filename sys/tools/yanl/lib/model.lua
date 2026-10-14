--
-- SPDX-License-Identifier: BSD-2-Clause
--
-- Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
--

--
-- The netlink model of a set of YANG modules.
--
-- Modules are found on a search path and loaded with their imports;
-- typedefs and groupings are resolved; the statements of
-- freebsd-netlink-extensions (nlx:) are read into attribute sets, fixed
-- headers and structures as lib/snl.lua wants them: every attribute with
-- its type number, C name and wire type, every structure with its
-- members and their sizes.
--

local yang = require("lib.yang")
local schema = require("lib.schema")

local model = {}

local fail = schema.fail
local where = yang.where

-- The modules whose extension statements are interpreted, by name, and
-- the short prefix the generator knows them by.
local known_ext_modules = {
	["freebsd-netlink-extensions"] = "nlx",
	["freebsd-netlink-snl"] = "snl",
}

-- Typedefs of freebsd-netlink-types with a meaning for the generator.
local types_module = "freebsd-netlink-types"
local bitset_module = "freebsd-netlink"

local builtin_types = {
	["uint8"] = {size = 1}, ["uint16"] = {size = 2},
	["uint32"] = {size = 4}, ["uint64"] = {size = 8},
	["int8"] = {size = 1, signed = true},
	["int16"] = {size = 2, signed = true},
	["int32"] = {size = 4, signed = true},
	["int64"] = {size = 8, signed = true},
	["boolean"] = {size = 1}, ["empty"] = {}, ["string"] = {},
	["binary"] = {}, ["enumeration"] = {}, ["bits"] = {},
	["union"] = {}, ["decimal64"] = {}, ["identityref"] = {},
	["leafref"] = {}, ["instance-identifier"] = {},
}

-- "rtm-family" -> "RTM_FAMILY"
function model.cUpper(name)
	return (name:upper():gsub("-", "_"))
end

-- "rtm-family" -> "rtm_family"
function model.cLower(name)
	return (name:lower():gsub("-", "_"))
end

--
-- Modules.
--
local Module = {}
Module.__index = Module

-- The canonical name ("nlx:attr") of an extension statement, or nil for
-- a YANG statement or an extension the generator does not know.
function Module:ext(stmt)
	if stmt.prefix == nil then
		return nil
	end
	local modname = self:moduleOfPrefix(stmt.prefix, stmt)
	local short = known_ext_modules[modname]

	if short == nil then
		return nil
	end
	return short .. ":" .. stmt.name
end

function Module:moduleOfPrefix(prefix, stmt)
	if prefix == self.prefix then
		return self.name
	end
	local modname = self.imports[prefix]

	if modname == nil then
		fail(where(stmt), "unknown prefix '%s'", prefix)
	end
	return modname
end

-- The first substatement of stmt that is the extension ext.
function Module:getExt(stmt, ext)
	for _, s in ipairs(stmt.subs) do
		if s.prefix ~= nil and self:ext(s) == ext then
			return s
		end
	end
	return nil
end

function Module:extArg(stmt, ext)
	local s = self:getExt(stmt, ext)

	return s and s.arg
end

function Module:hasExt(stmt, ext)
	return self:getExt(stmt, ext) ~= nil
end

-- Resolve "prefix:name" or "name" to a module and a name.
function Module:resolveRef(ref, stmt)
	local prefix, name = ref:match("^([^:]+):(.+)$")

	if prefix == nil then
		return self, ref
	end
	return self.model:module(self:moduleOfPrefix(prefix, stmt)), name
end

-- Search the scope chain of ctx, then the module, for a typedef or
-- grouping named name.
local function findInScope(ctx, kw, name)
	for i = #ctx.stack, 1, -1 do
		for _, s in ipairs(ctx.stack[i].subs) do
			if s.kw == kw and s.arg == name then
				return s
			end
		end
	end
	for _, s in ipairs(ctx.mod.stmt.subs) do
		if s.kw == kw and s.arg == name then
			return s
		end
	end
	return nil
end

-- The grouping ref names, with the context its contents are read in.
function Module:findGrouping(ref, ctx, stmt)
	local mod, name = self:resolveRef(ref, stmt)
	local g

	if mod == self then
		g = findInScope(ctx, "grouping", name)
	else
		g = findInScope({mod = mod, stack = {}}, "grouping", name)
	end
	if g == nil then
		fail(where(stmt), "unknown grouping '%s'", ref)
	end
	return g, {mod = mod, stack = {}}
end

--
-- Types.  The result says the base type, the size of an integer, the
-- width given to an enumeration or bits type, and the typedefs the type
-- goes through.
--
function Module:resolveType(typeStmt, ctx)
	local mod = self
	local info = {typedefs = {}}
	local seen = {}

	while true do
		local name = typeStmt.arg
		local builtin = builtin_types[name]

		if builtin ~= nil and typeStmt.prefix == nil then
			info.base = name
			info.size = builtin.size
			info.signed = builtin.signed
			break
		end
		local tmod, tname = mod:resolveRef(name, typeStmt)
		local td

		if tmod == mod then
			td = findInScope(ctx, "typedef", tname)
		else
			td = findInScope({mod = tmod, stack = {}}, "typedef",
			    tname)
		end
		if td == nil then
			fail(where(typeStmt), "unknown type '%s'", name)
		end
		if seen[td] then
			fail(where(typeStmt), "circular typedef '%s'", name)
		end
		seen[td] = true
		info.typedefs[#info.typedefs + 1] = {
			module = tmod.name,
			name = tname,
		}
		if info.width == nil then
			local w = tmod:extArg(td, "nlx:width")

			if w ~= nil then
				info.width = tonumber(w)
			end
		end
		typeStmt = yang.sub(td, "type")
		if typeStmt == nil then
			fail(where(td), "typedef without a type")
		end
		mod = tmod
		ctx = {mod = tmod, stack = {td}}
	end
	return info
end

function Module:typedefIs(info, module, name)
	for _, td in ipairs(info.typedefs) do
		if td.module == module and td.name == name then
			return true
		end
	end
	return false
end

--
-- Data nodes.
--
-- A node is a leaf, leaf-list, container, list, choice, case or
-- anydata statement read with the prefix in force: it knows whether it
-- is an attribute (attr ~= nil), its C name, its resolved type and its
-- children.
--
local data_kinds = {
	["leaf"] = true, ["leaf-list"] = true, ["container"] = true,
	["list"] = true, ["choice"] = true, ["case"] = true,
	["anydata"] = true, ["anyxml"] = true,
}

function Module:expandBody(stmt, ctx, prefix, parent)
	local nodes = {}
	local uses, others = 0, 0

	for _, s in ipairs(stmt.subs) do
		if s.kw == "uses" then
			local g, gctx = self:findGrouping(s.arg, ctx, s)
			local gprefix = gctx.mod:extArg(g, "nlx:name-prefix") or
			    prefix

			gctx = {mod = gctx.mod, stack = {g}}
			for _, n in ipairs(gctx.mod:expandBody(g, gctx, gprefix,
			    parent)) do
				nodes[#nodes + 1] = n
			end
			uses = uses + 1
			if parent ~= nil then
				parent.last_uses = {
					mod = gctx.mod, name = g.arg, stmt = g,
				}
			end
		elseif data_kinds[s.kw] then
			nodes[#nodes + 1] = self:node(s, {
				mod = ctx.mod, stack = ctx.stack,
			}, prefix)
			others = others + 1
		end
	end
	if parent ~= nil then
		-- A body that is one 'uses' takes the grouping's nature:
		-- a structure, a bitset, a message with a fixed header.
		parent.uses_grouping = (uses == 1 and others == 0) and
		    parent.last_uses or nil
	end
	return nodes
end

function Module:node(stmt, ctx, prefix)
	local n = {
		kind = stmt.kw,
		name = stmt.arg,
		stmt = stmt,
		mod = self,
		children = {},
	}
	local attr = self:extArg(stmt, "nlx:attr")
	local cname = self:extArg(stmt, "nlx:c-name")
	local subctx = {mod = ctx.mod, stack = {}}

	for i, s in ipairs(ctx.stack) do
		subctx.stack[i] = s
	end
	subctx.stack[#subctx.stack + 1] = stmt

	if attr ~= nil then
		n.attr = tonumber(attr)
		if n.attr == nil then
			fail(where(stmt), "nlx:attr is not a number: '%s'",
			    attr)
		end
		n.c_name = cname or (prefix or "") .. model.cUpper(n.name)
	else
		n.c_name = cname or model.cLower(n.name)
	end
	n.struct = self:extArg(stmt, "nlx:struct")
	n.array = self:hasExt(stmt, "nlx:array")
	n.fixed_header = self:extArg(stmt, "nlx:fixed-header")
	if n.fixed_header ~= nil then
		n.fixed_header_mod = self
		n.fixed_header_stmt = stmt
	end
	n.width = tonumber(self:extArg(stmt, "nlx:width") or "")

	if stmt.kw == "leaf" or stmt.kw == "leaf-list" then
		local t = yang.sub(stmt, "type")

		if t == nil then
			fail(where(stmt), "%s without a type", stmt.kw)
		end
		n.type = self:resolveType(t, subctx)
	elseif stmt.kw ~= "anydata" and stmt.kw ~= "anyxml" then
		local childPrefix = self:extArg(stmt, "nlx:name-prefix") or
		    prefix

		n.children = self:expandBody(stmt, subctx, childPrefix, n)
		if n.uses_grouping ~= nil then
			local g = n.uses_grouping
			local gm = g.mod

			n.struct = n.struct or gm:extArg(g.stmt, "nlx:struct")
			if n.fixed_header == nil then
				n.fixed_header = gm:extArg(g.stmt,
				    "nlx:fixed-header")
				n.fixed_header_mod = gm
				n.fixed_header_stmt = g.stmt
			end
		end
	end
	return n
end

--
-- Structures: a grouping marked nlx:struct, its leaves the members.
--
function Module:structOf(ref, stmt, ctx)
	local g, gctx = self:findGrouping(ref, ctx or {mod = self,
	    stack = {}}, stmt)
	local gm = gctx.mod
	local cname = gm:extArg(g, "nlx:struct")
	local key = gm.name .. ":" .. g.arg

	if self.model.structs[key] ~= nil then
		return self.model.structs[key]
	end
	if cname == nil then
		fail(where(stmt), "grouping '%s' is not a structure (no " ..
		    "nlx:struct)", ref)
	end
	local st = {
		name = g.arg,
		c_name = cname,
		module = gm,
		members = {},
		by_name = {},
	}

	for _, n in ipairs(gm:expandBody(g, {mod = gm, stack = {g}}, nil,
	    nil)) do
		if n.attr ~= nil then
			fail(where(n.stmt), "attribute inside structure '%s'",
			    cname)
		end
		local m = {name = n.name, c_name = n.c_name, node = n}

		if n.type ~= nil then
			m.size = n.type.size
			m.signed = n.type.signed
			if (n.type.base == "enumeration" or
			    n.type.base == "bits") then
				m.size = (n.width or n.type.width or 32) // 8
			end
		end
		st.members[#st.members + 1] = m
		st.by_name[m.name] = m
	end
	self.model.structs[key] = st
	return st
end

--
-- Attribute sets, as lib/snl.lua reads them: attr.type is the ynl
-- type name, attr.value the type number, attr.nested the set of a nest.
--
local AttrSet = {}
AttrSet.__index = AttrSet

function AttrSet:attr(name)
	return self.by_name[name]
end

local ip_typedefs = {
	["ip-address"] = "ipv4-or-v6",
	["in-addr"] = "in_addr",
	["in6-addr"] = "in6_addr",
	["rtvia"] = "via",
	["time-t"] = "time_t",
}

-- The ynl type of a leaf, from its YANG type.
local function leafType(n)
	local t = n.type
	local base = t.base
	local hint

	for _, td in ipairs(t.typedefs) do
		if td.module == types_module and ip_typedefs[td.name] then
			hint = ip_typedefs[td.name]
			break
		end
	end
	if base == "boolean" then
		return "bool"
	elseif base == "empty" then
		return "flag"
	elseif base == "string" then
		return "string"
	elseif base == "binary" then
		return "binary", hint
	elseif base == "enumeration" or base == "bits" then
		return "u" .. tostring(n.width or t.width or 32)
	elseif base:match("^uint%d+$") then
		return "u" .. base:sub(5)
	elseif base:match("^int%d+$") then
		return "s" .. base:sub(4)
	end
	fail(where(n.stmt), "no wire type for a leaf of type '%s'", base)
end

local function isBitset(n)
	local g = n.uses_grouping

	return g ~= nil and g.mod.name == bitset_module and g.name == "bitset"
end

function model.attrSetOf(nodes, name, mod)
	local set = setmetatable({
		name = name,
		module = mod,
		attrs = {},
		by_name = {},
	}, AttrSet)
	local function add(n)
		local attr = {
			name = n.name,
			value = n.attr,
			c_name = n.c_name,
			set = set,
			node = n,
			doc = nil,
		}

		if n.kind == "leaf" then
			attr.type, attr.display_hint = leafType(n)
		elseif n.kind == "leaf-list" then
			attr.type, attr.display_hint = leafType(n)
			if n.array then
				attr.sub_type = attr.type
				attr.type = "indexed-array"
			else
				attr.multi = true
			end
		elseif n.kind == "anydata" or n.kind == "anyxml" then
			attr.type = "binary"
		elseif n.kind == "choice" then
			attr.type = "sub-message"
		elseif n.kind == "container" then
			if n.struct ~= nil then
				attr.type = "binary"
				attr.struct = n.struct
			elseif isBitset(n) then
				attr.type = "bitset"
			else
				attr.type = "nest"
				attr.nested = model.attrSetOf(n.children,
				    name .. "/" .. n.name, mod)
			end
		elseif n.kind == "list" then
			if n.struct ~= nil then
				attr.type = "binary"
				attr.struct = n.struct
			elseif n.array then
				attr.type = "indexed-array"
				attr.sub_type = "nest"
				attr.nested = model.attrSetOf(n.children,
				    name .. "/" .. n.name, mod)
				if n.fixed_header ~= nil then
					attr.header = n.fixed_header_mod:structOf(
					    n.fixed_header, n.fixed_header_stmt)
				end
			else
				attr.type = "nest"
				attr.multi = true
				attr.nested = model.attrSetOf(n.children,
				    name .. "/" .. n.name, mod)
			end
		end
		if set.by_name[attr.name] ~= nil then
			fail(where(n.stmt), "duplicate attribute '%s'", n.name)
		end
		set.attrs[#set.attrs + 1] = attr
		set.by_name[attr.name] = attr
	end
	local function walk(list)
		for _, n in ipairs(list) do
			if n.attr ~= nil then
				add(n)
			elseif n.kind == "choice" or n.kind == "case" then
				-- Exclusive attributes, still one set.
				walk(n.children)
			end
		end
	end
	walk(nodes)
	return set
end

--
-- A grouping as the binding sees it: its fixed header, if any, and its
-- attribute set.
--
function Module:groupingOf(ref, stmt)
	local g, gctx = self:findGrouping(ref, {mod = self, stack = {}},
	    stmt)
	local gm = gctx.mod
	local key = gm.name .. ":" .. g.arg

	if self.model.groupings[key] ~= nil then
		return self.model.groupings[key]
	end
	local r = {
		name = g.arg,
		module = gm,
		stmt = g,
		doc = yang.sub(g, "description") and
		    yang.sub(g, "description").arg,
	}
	local nodes = gm:expandBody(g, {mod = gm, stack = {g}},
	    gm:extArg(g, "nlx:name-prefix"), nil)
	local hdr = gm:extArg(g, "nlx:fixed-header")

	if hdr ~= nil then
		r.header = gm:structOf(hdr, g)
	end
	r.set = model.attrSetOf(nodes, g.arg, gm)
	self.model.groupings[key] = r
	return r
end

--
-- The model: a set of modules on a search path.
--
local Model = {}
Model.__index = Model

function model.new(paths)
	return setmetatable({
		paths = paths,
		modules = {},
		structs = {},
		groupings = {},
	}, Model)
end

local function readFile(path)
	local fh = io.open(path, "r")

	if fh == nil then
		return nil
	end
	local data = fh:read("a")
	fh:close()
	return data
end

local function basename(path)
	return path:match("([^/]+)$")
end

local function dirname(path)
	return path:match("^(.*)/[^/]+$") or "."
end

-- Find the file of module name on the search path: name.yang, or the
-- newest name@revision.yang.
function Model:find(name)
	for _, dir in ipairs(self.paths) do
		local plain = dir .. "/" .. name .. ".yang"

		if readFile(plain) ~= nil then
			return plain
		end
		local best
		local p = io.popen(string.format("ls -1 '%s' 2>/dev/null",
		    dir))

		if p ~= nil then
			for f in p:lines() do
				local rev = f:match("^" ..
				    name:gsub("%-", "%%-") ..
				    "@(%d%d%d%d%-%d%d%-%d%d)%.yang$")

				if rev ~= nil and (best == nil or rev > best.rev)
				    then
					best = {rev = rev, path = dir .. "/" .. f}
				end
			end
			p:close()
		end
		if best ~= nil then
			return best.path
		end
	end
	return nil
end

function Model:addPath(dir)
	for _, d in ipairs(self.paths) do
		if d == dir then
			return
		end
	end
	self.paths[#self.paths + 1] = dir
end

-- Load a module by file name (with a .yang suffix or a slash) or by
-- module name; its imports are loaded with it.
function Model:load(what, from)
	local path

	if what:find("/", 1, true) or what:match("%.yang$") then
		path = what
	else
		if self.modules[what] ~= nil then
			return self.modules[what]
		end
		path = self:find(what)
		if path == nil then
			fail(from, "module '%s' not found on the search path " ..
			    "(%s)", what, table.concat(self.paths, ", "))
		end
	end
	local text = readFile(path)

	if text == nil then
		fail(from, "cannot read %s", path)
	end
	self:addPath(dirname(path))

	local stmt = yang.parse(text, basename(path))
	local mod = setmetatable({
		model = self,
		name = stmt.arg,
		stmt = stmt,
		path = path,
		basename = basename(path),
		imports = {},
		license = text:match("SPDX%-License%-Identifier:%s*([^\n]-)%s*\n"),
	}, Module)
	local prefix = yang.sub(stmt, "prefix")
	local desc = yang.sub(stmt, "description")

	if stmt.kw ~= "module" then
		fail(mod.basename, "submodules are not supported")
	end
	if prefix == nil then
		fail(mod.basename, "module without a prefix")
	end
	mod.prefix = prefix.arg
	mod.doc = desc and desc.arg
	if self.modules[mod.name] ~= nil then
		return self.modules[mod.name]
	end
	self.modules[mod.name] = mod

	for _, imp in ipairs(yang.subs(stmt, "import")) do
		local p = yang.sub(imp, "prefix")

		if p == nil then
			fail(where(imp), "import without a prefix")
		end
		mod.imports[p.arg] = imp.arg
		self:load(imp.arg, where(imp))
	end
	for _, inc in ipairs(yang.subs(stmt, "include")) do
		fail(where(inc), "submodules are not supported")
	end
	return mod
end

function Model:module(name)
	local mod = self.modules[name]

	if mod == nil then
		fail(nil, "module '%s' is not loaded", name)
	end
	return mod
end

return model
