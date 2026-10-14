--
-- SPDX-License-Identifier: BSD-2-Clause
--
-- Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
--

--
-- A YANG parser (RFC 7950, section 6 and 14): the text of a module
-- becomes a tree of statements, each a keyword, an argument and its
-- substatements.  Nothing is interpreted here; lib/model.lua does that.
--

local schema = require("lib.schema")

local yang = {}

local fail = schema.fail

local Parser = {}
Parser.__index = Parser

local function newParser(text, name)
	return setmetatable({
		text = text,
		name = name,
		pos = 1,
		line = 1,
		linestart = 1,	-- position of the first character of line
	}, Parser)
end

function Parser:where()
	return string.format("%s:%d", self.name, self.line)
end

function Parser:fail(fmt, ...)
	fail(self:where(), fmt, ...)
end

-- Move to position p, counting the lines passed.
function Parser:advance(p)
	local text = self.text

	while true do
		local nl = text:find("\n", self.pos, true)

		if nl == nil or nl >= p then
			break
		end
		self.line = self.line + 1
		self.linestart = nl + 1
		self.pos = nl + 1
	end
	self.pos = p
end

-- Display column of position p on its line, tabs being 8 wide, from 0.
function Parser:column(p)
	local col = 0

	for i = self.linestart, p - 1 do
		if self.text:byte(i) == 9 then
			col = col - col % 8 + 8
		else
			col = col + 1
		end
	end
	return col
end

-- Skip whitespace and comments.
function Parser:skip()
	local text = self.text

	while true do
		local p = text:find("[^ \t\r\n]", self.pos)

		if p == nil then
			self:advance(#text + 1)
			return
		end
		self:advance(p)
		local two = text:sub(p, p + 1)
		if two == "//" then
			local e = text:find("\n", p, true)

			self:advance(e == nil and #text + 1 or e)
		elseif two == "/*" then
			local e = text:find("*/", p + 2, true)

			if e == nil then
				self:fail("unterminated comment")
			end
			self:advance(e + 2)
		else
			return
		end
	end
end

function Parser:peek()
	return self.text:sub(self.pos, self.pos)
end

local escapes = {n = "\n", t = "\t", ['"'] = '"', ["\\"] = "\\"}

-- A double-quoted string: indentation trimmed, escapes replaced.
function Parser:doubleQuoted()
	local text = self.text
	local col = self:column(self.pos)
	local start = self.pos + 1
	local p = start

	while true do
		local c = text:sub(p, p)

		if c == "" then
			self:fail("unterminated string")
		elseif c == "\\" then
			p = p + 2
		elseif c == '"' then
			break
		else
			p = p + 1
		end
	end
	local raw = text:sub(start, p - 1)
	self:advance(p + 1)

	-- RFC 7950, 6.1.3: strip trailing whitespace before a line break
	-- and the indentation of continuation lines up to the column of
	-- the opening quote.
	local lines = {}
	for l in (raw .. "\n"):gmatch("(.-)\n") do
		lines[#lines + 1] = l
	end
	for i = 1, #lines do
		if i < #lines then
			lines[i] = lines[i]:gsub("[ \t]+$", "")
		end
		if i > 1 then
			local l = lines[i]
			local c = 0
			local j = 1

			while j <= #l and c <= col do
				local b = l:byte(j)

				if b == 32 then
					c = c + 1
				elseif b == 9 then
					c = c - c % 8 + 8
				else
					break
				end
				j = j + 1
			end
			lines[i] = l:sub(j)
		end
	end
	local s = table.concat(lines, "\n")
	return (s:gsub("\\(.)", function(c)
		return escapes[c] or ("\\" .. c)
	end))
end

function Parser:singleQuoted()
	local e = self.text:find("'", self.pos + 1, true)

	if e == nil then
		self:fail("unterminated string")
	end
	local s = self.text:sub(self.pos + 1, e - 1)
	self:advance(e + 1)
	return s
end

function Parser:quoted()
	local c = self:peek()

	if c == '"' then
		return self:doubleQuoted()
	elseif c == "'" then
		return self:singleQuoted()
	end
	return nil
end

function Parser:unquoted()
	local text = self.text
	local p = self.pos

	while true do
		local c = text:sub(p, p)

		if c == "" or c:match("[ \t\r\n;{}\"']") then
			break
		end
		local two = text:sub(p, p + 1)
		if two == "//" or two == "/*" or two == "*/" then
			break
		end
		p = p + 1
	end
	if p == self.pos then
		self:fail("expected an argument, got '%s'", text:sub(p, p))
	end
	local s = text:sub(self.pos, p - 1)
	self:advance(p)
	return s
end

-- The argument of a statement, if any: a quoted string, possibly
-- several joined by '+', or an unquoted one.
function Parser:argument()
	self:skip()
	local c = self:peek()

	if c == ";" or c == "{" then
		return nil
	end
	if c == '"' or c == "'" then
		local s = self:quoted()

		while true do
			self:skip()
			if self:peek() ~= "+" then
				break
			end
			self:advance(self.pos + 1)
			self:skip()
			local more = self:quoted()
			if more == nil then
				self:fail("expected a string after '+'")
			end
			s = s .. more
		end
		return s
	end
	return self:unquoted()
end

function Parser:statement()
	local line = self.line
	local kw = self.text:match("^[%a_][%w%._%-]*:?[%a_][%w%._%-]*", self.pos)
	    or self.text:match("^[%a_][%w%._%-]*", self.pos)

	if kw == nil then
		self:fail("expected a statement, got '%s'", self:peek())
	end
	self:advance(self.pos + #kw)

	local prefix, name = kw:match("^([^:]+):(.+)$")
	local stmt = {
		kw = kw,
		prefix = prefix,
		name = name or kw,
		arg = self:argument(),
		subs = {},
		line = line,
		file = self.name,
	}

	self:skip()
	local c = self:peek()
	if c == ";" then
		self:advance(self.pos + 1)
	elseif c == "{" then
		self:advance(self.pos + 1)
		while true do
			self:skip()
			if self:peek() == "}" then
				self:advance(self.pos + 1)
				break
			elseif self:peek() == "" then
				self:fail("unterminated block of '%s' (line %d)",
				    kw, line)
			end
			stmt.subs[#stmt.subs + 1] = self:statement()
		end
	else
		self:fail("expected ';' or '{' after '%s', got '%s'", kw,
		    c == "" and "end of file" or c)
	end
	return stmt
end

-- Parse the text of a module; returns its module (or submodule)
-- statement.
function yang.parse(text, name)
	local p = newParser(text, name)

	p:skip()
	local stmt = p:statement()
	p:skip()
	if p:peek() ~= "" then
		p:fail("text after the module statement")
	end
	if stmt.kw ~= "module" and stmt.kw ~= "submodule" then
		p:fail("not a module: starts with '%s'", stmt.kw)
	end
	return stmt
end

-- The first substatement of stmt with keyword kw, if any.
function yang.sub(stmt, kw)
	for _, s in ipairs(stmt.subs) do
		if s.kw == kw then
			return s
		end
	end
	return nil
end

-- Every substatement of stmt with keyword kw.
function yang.subs(stmt, kw)
	local r = {}

	for _, s in ipairs(stmt.subs) do
		if s.kw == kw then
			r[#r + 1] = s
		end
	end
	return r
end

function yang.where(stmt)
	return string.format("%s:%d", stmt.file, stmt.line)
end

return yang
