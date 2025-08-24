# Security Review Report

## Problems Found:

1. **SQL Injection Risk** - Hackers can steal data
2. **Weak Password Hashing** - MD5 is easy to break  
3. **Debug Mode Enabled** - Shows too much information

## Fixes Applied:

1. ✅ Used parameterized queries to stop SQL injection
2. ✅ Used bcrypt for strong password hashing
3. ✅ Turned off debug mode for production