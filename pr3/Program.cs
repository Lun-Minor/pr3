using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using pr3;
using pr3.Models;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text.Json.Serialization;


//токен менеджера 2
//"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiI3IiwibmFtZSI6Im1hbmFnZXIyIiwicm9sZSI6Ik1hbmFnZXIiLCJleHAiOjE3OTI1NzkyMDQsImlzcyI6Ikp3dERlbW8iLCJhdWQiOiJKd3REZW1vQXBpIn0.Bw2Bm5Bi78X0FkT_UIJqMZNVmpL71qSqR6AHErCiSDM"

var builder = WebApplication.CreateBuilder(args);


builder.Services.ConfigureHttpJsonOptions(options =>
{
    options.SerializerOptions.ReferenceHandler = ReferenceHandler.IgnoreCycles;
});


builder.Services.AddDbContext<Clothes_ShopContext>();

var hasher = new PasswordHasher<User>();

var key = new SymmetricSecurityKey(RandomNumberGenerator.GetBytes(32));

var validation = new TokenValidationParameters
{
    ValidateIssuer = true,
    ValidIssuer = "JwtDemo",

    ValidateAudience = true,
    ValidAudience = "JwtDemoApi",

    ValidateIssuerSigningKey = true,
    IssuerSigningKey = key,

    ValidateLifetime = true,
    ClockSkew = TimeSpan.Zero,

    NameClaimType = "name",
    RoleClaimType = "role"
};

builder.Services
    .AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(options =>
    {
        options.MapInboundClaims = false;
        options.TokenValidationParameters = validation;
    });

builder.Services.AddAuthorization();

var app = builder.Build();

app.UseAuthentication();
app.UseAuthorization();


app.MapPost("/reg", async (Clothes_ShopContext db, RegRequest request) =>
{
    if (string.IsNullOrWhiteSpace(request.Login) ||
        string.IsNullOrWhiteSpace(request.Password) ||
        string.IsNullOrWhiteSpace(request.Phone) ||
        string.IsNullOrWhiteSpace(request.Address))
        return Results.BadRequest(new { message = "Заполните все поля" });

    if (await db.Users.AnyAsync(u => u.Login == request.Login))
        return Results.BadRequest(new { message = "Такой логин уже занят" });

    var role = await db.Roles.FirstOrDefaultAsync(r => r.Name == "User");
   

    var newUser = new User
    {
        Login = request.Login,
        Phone = request.Phone,
        Adress = request.Address,
        IdRole = role.Id
    };
    newUser.Password = hasher.HashPassword(newUser, request.Password);

    db.Users.Add(newUser);
    await db.SaveChangesAsync();

    return Results.Created($"/users{newUser.Id}", new { id = newUser.Id, login = newUser.Login });
}).AllowAnonymous();


app.MapPost("/login", async (Clothes_ShopContext db, LoginRequest request) =>
{
    var account = await db.Users.Include(u => u.IdRoleNavigation).FirstOrDefaultAsync(u => u.Login == request.Login);

    if (account == null || string.IsNullOrWhiteSpace(request.Password)) return Results.Challenge();

    var result = hasher.VerifyHashedPassword(account, account.Password, request.Password);

    if (result == PasswordVerificationResult.Failed) return Results.Challenge();

    return Results.Ok(new
    {
        access_token = CreateToken(account),
        token_type = "Bearer"
    });
}).AllowAnonymous();



app.MapPatch("/clothes/{id}/remove", async (Clothes_ShopContext db, int id) =>
{
    var clothe = await db.Clothes.FirstOrDefaultAsync(c => c.Id == id);
    if (clothe == null) return Results.NotFound(new { message = "Товар не найден" });

    clothe.Status = 0;
    await db.SaveChangesAsync();
    return Results.Ok(new { message = "Товар убран" });
}).RequireAuthorization(policy => policy.RequireAuthenticatedUser().RequireRole("Manager"));


app.MapPatch("/clothes/{id}/return", async (Clothes_ShopContext db, int id) =>
{
    var clothe = await db.Clothes.FirstOrDefaultAsync(c => c.Id == id);
    if (clothe == null) return Results.NotFound(new { message = "Товар не найден" });

    clothe.Status = 1;
    await db.SaveChangesAsync();
    return Results.Ok(new { message = "Товар возвращён в продажу" });
}).RequireAuthorization(policy => policy.RequireAuthenticatedUser().RequireRole("Manager"));




app.MapPatch("/clothes/{clothesId}/sizes/{sizeId}/quantity",
    async (Clothes_ShopContext db, int clothesId, int sizeId, UpdateQuantity request) =>
    {

        var sizeClothe = await db.SizesClothes.FirstOrDefaultAsync(s => s.IdClothes == clothesId && s.IdSizes == sizeId);

        if (sizeClothe == null) return Results.NotFound(new { message = "У товара нет такого размера" });

        if (request.Quantity < 0) return Results.BadRequest(new { message = "Количество не может быть отрицательным" });

        sizeClothe.Quantity = request.Quantity;
        await db.SaveChangesAsync();

        return Results.Json(sizeClothe);
    }).RequireAuthorization(policy => policy.RequireAuthenticatedUser().RequireRole("Manager"));


app.MapPatch("/orders/{id}/status", async (Clothes_ShopContext db, int id, UpdateStatus request) =>
{
    var order = await db.Orders.FirstOrDefaultAsync(o => o.Id == id);
    if (order == null) return Results.NotFound(new { message = "Заказ не найден" });

    if (!await db.Statuses.AnyAsync(s => s.Id == request.StatusId))
        return Results.BadRequest(new { message = "Такого статуса нет" });

    order.IdStatus = request.StatusId;
    await db.SaveChangesAsync();

    return Results.Ok(new { id = order.Id, statusId = order.IdStatus });
}).RequireAuthorization(policy => policy.RequireAuthenticatedUser().RequireRole("Manager"));



app.Run();



string CreateToken(User account)
{
    var claims = new[]
    {
        new Claim("sub", account.Id.ToString()),
        new Claim("name", account.Login),
        new Claim("role", account.IdRoleNavigation.Name)
    };

    var token = new JwtSecurityToken(
        issuer: "JwtDemo",
        audience: "JwtDemoApi",
        claims: claims,
        expires: DateTime.UtcNow.AddMinutes(60),
        signingCredentials: new SigningCredentials(
            key, SecurityAlgorithms.HmacSha256));

    return new JwtSecurityTokenHandler().WriteToken(token);
}


//