#!/usr/libexec/flua
--
-- SPDX-License-Identifier: BSD-2-Clause
--
-- Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
--

--
-- yanl: generate a header of snl(3) parsers from YANG descriptions of
-- netlink protocols and their snl binding modules.  See README.md.
--

-- Add the script directory to the module search path.
local path = arg[0]:match("^(.*)/[^/]+$") or "."
package.path = path .. "/?.lua;" .. package.path

local model = require("lib.model")
local schema = require("lib.schema")
local snl = require("lib.snl")

local progname = arg[0]:match("([^/]+)$")

local function usage()
	io.stderr:write(string.format(
	    "usage: %s [-p path] [-g guard] [-o output] binding ...\n",
	    progname))
	os.exit(1)
end

local function parseArgs(argv)
	local opts = {bindings = {}, paths = {}}
	local i = 1

	while i <= #argv do
		local a = argv[i]

		if a == "-o" or a == "-g" or a == "-p" then
			if argv[i + 1] == nil then
				usage()
			end
			if a == "-p" then
				opts.paths[#opts.paths + 1] = argv[i + 1]
			else
				opts[a == "-o" and "output" or "guard"] =
				    argv[i + 1]
			end
			i = i + 1
		elseif a:sub(1, 1) == "-" then
			usage()
		else
			opts.bindings[#opts.bindings + 1] = a
		end
		i = i + 1
	end
	if #opts.bindings == 0 then
		usage()
	end
	return opts
end

-- "netlink_snl_route_parsers.h" -> "_NETLINK_NETLINK_SNL_ROUTE_PARSERS_H_"
local function defaultGuard(opts, first)
	local name

	if opts.output ~= nil then
		name = opts.output:match("([^/]+)$")
	else
		name = first.basename:gsub("%.yang$", "") .. ".h"
	end
	return "_NETLINK_" .. name:upper():gsub("[^%w]", "_") .. "_"
end

local function generate(opts)
	local m = model.new(opts.paths)
	local gen = snl.new()
	local first

	for _, name in ipairs(opts.bindings) do
		local mod = m:load(name)
		local b = snl.readBinding(mod)

		gen:addBinding(b)
		first = first or b
	end
	return gen:render(opts.guard or defaultGuard(opts, first),
	    progname)
end

local opts = parseArgs(arg)
local ok, text = xpcall(generate, function(err)
	if schema.isError(err) then
		return err
	end
	return debug.traceback(tostring(err), 2)
end, opts)

if not ok then
	io.stderr:write(string.format("%s: %s\n", progname, tostring(text)))
	os.exit(1)
end

if opts.output ~= nil then
	local fh, err = io.open(opts.output, "w")

	if fh == nil then
		io.stderr:write(string.format("%s: %s\n", progname, err))
		os.exit(1)
	end
	assert(fh:write(text))
	assert(fh:close())
else
	io.write(text)
end
