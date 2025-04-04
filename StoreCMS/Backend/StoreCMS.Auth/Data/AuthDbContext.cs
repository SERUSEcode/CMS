using System.Collections.Generic;
using Microsoft.EntityFrameworkCore;
using StoreCMS.Common.Models;

namespace StoreCMS.Auth.Data;

public class AuthDbContext : DbContext
{
    public AuthDbContext(DbContextOptions<AuthDbContext> options)
    : base(options)
    {
    }

    public DbSet<User> Users => Set<User>();
    public DbSet<LogEntry> Logs => Set<LogEntry>(); // our logging table
}
