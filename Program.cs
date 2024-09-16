using Microsoft.EntityFrameworkCore;
using VulnerableApp.Data;
using Microsoft.AspNetCore.Http;
using VulnerableApp.Models;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
// Add EF Core with SQLite
builder.Services.AddDbContext<ApplicationDbContext>(options =>
    options.UseSqlite(builder.Configuration.GetConnectionString("DefaultConnection")));

// Add session management
builder.Services.AddDistributedMemoryCache();
builder.Services.AddSession(options =>
{
    options.IdleTimeout = TimeSpan.FromMinutes(30); 
    options.Cookie.HttpOnly = true;
    options.Cookie.IsEssential = true;
    options.Cookie.SameSite = SameSiteMode.None;  // Disable SameSite restrictions
    options.Cookie.SecurePolicy = CookieSecurePolicy.SameAsRequest;  // Set to SameAsRequest for non-HTTPS environments //WHEN CHANGING THE COOKIE SETTINGS MALICIOUS HTML FORM STARTS WORKING.
});

// Add services to the container.
builder.Services.AddControllersWithViews();

var app = builder.Build();

// Seed the database with default admin and user accounts
using (var scope = app.Services.CreateScope())
{
    var services = scope.ServiceProvider;

    // Call the SeedData class to initialize the database with seed data
    SeedData.Initialize(services);
}

// Configure the HTTP request pipeline.
if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Home/Error");
    // The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
    app.UseHsts();
}

app.UseHttpsRedirection();
app.UseStaticFiles();

app.UseRouting();

// Use session before authorization and mapping routes
app.UseSession();

app.UseAuthorization();

app.MapControllerRoute(
    name: "default",
    pattern: "{controller=Home}/{action=Dashboard}/{id?}");

app.Run();
