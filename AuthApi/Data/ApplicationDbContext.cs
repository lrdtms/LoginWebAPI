using Microsoft.EntityFrameworkCore;
using AuthApi.Models;

namespace AuthApi.Data // ✅ Adjust to your actual folder/namespace
{
    public class ApplicationDbContext : DbContext
    {
        public ApplicationDbContext(DbContextOptions<ApplicationDbContext> options)
            : base(options)
        {
        }

        public DbSet<User> Users { get; set; }
    }
}