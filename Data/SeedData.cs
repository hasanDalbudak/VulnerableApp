using Microsoft.EntityFrameworkCore;
using VulnerableApp.Models;
using System;

namespace VulnerableApp.Data
{
    public static class SeedData
    {
        public static void Initialize(IServiceProvider serviceProvider)
        {
            using (var context = new ApplicationDbContext(
                serviceProvider.GetRequiredService<DbContextOptions<ApplicationDbContext>>()))
            {
                // Apply pending migrations
                if (context.Database.GetPendingMigrations().Any())
                {
                    context.Database.Migrate();
                }

                // Seed default admin and user accounts if they don't exist
                if (!context.Users.Any())
                {
                    context.Users.AddRange(
                        new User
                        {
                            Username = "admin",
                            Password = "adminpass", // Ideally, use hashed passwords
                            Role = "admin"
                        },
                        new User
                        {
                            Username = "user",
                            Password = "userpass",
                            Role = "user"
                        },
                        new User
                        {
                            Username = "hasan",
                            Password = "hasanpass",
                            Role = "user"
                        });

                    context.SaveChanges();
                }
            }
        }
    }
}
