// minimal stand-in for a SQL client: query(sql, params?, cb)
module.exports = { query: (sql, params, cb) => (typeof params === "function" ? params : cb)(null, []) };
