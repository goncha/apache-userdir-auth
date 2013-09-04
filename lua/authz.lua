require "apache2"

function authz_check_owner(r)
  if r.method == 'GET' or r.method == 'HEAD' or r.method == 'OPTIONS' then
    -- Open methods of WebDAV
    return apache2.AUTHZ_GRANTED
  else
    -- Priviledged methods of WebDAV
    -- PUT, DELETE, ...
    if r.user == nil then
      -- Require authentication
      return apache2.AUTHZ_DENIED_NO_USER
    elseif r:regex(r.uri, '^/people/' .. r.user .. '/') then
      -- Match authenticated user to home directory
      return apache2.AUTHZ_GRANTED
    else
      return apache2.AUTHZ_DENIED
    end
  end
end
