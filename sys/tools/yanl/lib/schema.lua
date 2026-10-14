--
-- SPDX-License-Identifier: BSD-2-Clause
--
-- Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
--

--
-- Errors of the specs: raised with a location and reported without a
-- traceback.
--

local schema = {}

local SpecError = {}
SpecError.__index = SpecError
SpecError.__tostring = function(e)
	return e.msg
end

-- Raise a spec error; the generator reports these without a traceback.
function schema.fail(path, fmt, ...)
	local msg = string.format(fmt, ...)

	if path ~= nil and path ~= "" then
		msg = path .. ": " .. msg
	end
	error(setmetatable({msg = msg}, SpecError), 0)
end

function schema.isError(e)
	return getmetatable(e) == SpecError
end

return schema
