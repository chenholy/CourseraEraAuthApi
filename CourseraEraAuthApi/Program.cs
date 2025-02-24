using System.Text.Encodings.Web;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddDbContext<IdentityDbContext>(
    options => options.UseInMemoryDatabase("AppDb"));

builder.Services.AddIdentity<IdentityUser, IdentityRole>()
    .AddEntityFrameworkStores<IdentityDbContext>()
    .AddApiEndpoints();

// builder.Services.AddIdentityApiEndpoints<IdentityUser>()
//     .AddEntityFrameworkStores<IdentityDbContext>();

builder.Services.AddAuthorization(options =>
{
    options.AddPolicy("RequireAdminRole", policy => policy.RequireRole("Admin"));
});

var app = builder.Build();

app.MapIdentityApi<IdentityUser>();

app.MapGet("/", () => "Public Root");

app.MapGet("/protected", () => "Protected Root")
    .RequireAuthorization();

app.MapGet("/admin", () => "Admin Root")
    .RequireAuthorization("RequireAdminRole");

// Route to create an admin user with parameters
app.MapPost("/create-admin", async (AdminCreationRequest request, UserManager<IdentityUser> userManager, RoleManager<IdentityRole> roleManager) =>
{
    // Encode inputs to prevent XSS
    var encodedEmail = HtmlEncoder.Default.Encode(request.AdminEmail);
    var encodedPassword = HtmlEncoder.Default.Encode(request.AdminPassword);

    // Use parameterized queries (handled by EF Core)
    var adminUser = await userManager.FindByEmailAsync(encodedEmail);
    if (adminUser == null)
    {
        adminUser = new IdentityUser { UserName = encodedEmail, Email = encodedEmail };
        var createAdminResult = await userManager.CreateAsync(adminUser, encodedPassword);

        if (!createAdminResult.Succeeded)
        {
            return Results.BadRequest("Failed to create admin user");
        }
    }

    var roleExists = await roleManager.RoleExistsAsync("Admin");
    if (!roleExists)
    {
        var roleResult = await roleManager.CreateAsync(new IdentityRole("Admin"));
        if (!roleResult.Succeeded)
        {
            return Results.BadRequest("Failed to create Admin role");
        }
    }

    if (!await userManager.IsInRoleAsync(adminUser, "Admin"))
    {
        var addToRoleResult = await userManager.AddToRoleAsync(adminUser, "Admin");
        if (!addToRoleResult.Succeeded)
        {
            return Results.BadRequest("Failed to add admin user to Admin role");
        }
    }
    return Results.Ok("Admin user created and assigned to Admin role");
});

app.Run();

// Model for admin creation request
public class AdminCreationRequest
{
    public string AdminEmail { get; set; }
    public string AdminPassword { get; set; }
}