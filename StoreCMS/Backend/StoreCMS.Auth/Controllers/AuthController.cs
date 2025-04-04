using Microsoft.AspNetCore.Mvc;
using StoreCMS.Auth.Data;
using StoreCMS.Common.Models;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using Microsoft.AspNetCore.Authorization;

namespace StoreCMS.Auth.Controllers;

[ApiController]
[Route("api/[controller]")]
public class AuthController : ControllerBase
{
    private readonly AuthDbContext _db;
    private readonly IConfiguration _config;

    public AuthController(AuthDbContext db, IConfiguration config)
    {
        _db = db;
        _config = config;
    }

    [HttpPost("register")]
    public async Task<IActionResult> Register([FromBody] User user)
    {
        if (_db.Users.Any(u => u.Email == user.Email))
            return Conflict("User already exists");

        user.PasswordHash = BCrypt.Net.BCrypt.HashPassword(user.PasswordHash);
        _db.Users.Add(user);
        await _db.SaveChangesAsync();
        return Ok("User registered");
    }

    [HttpPost("login")]
    public IActionResult Login([FromBody] User userInput)
    {
        var user = _db.Users.FirstOrDefault(u => u.Email == userInput.Email);
        if (user == null || !BCrypt.Net.BCrypt.Verify(userInput.PasswordHash, user.PasswordHash))
            return Unauthorized("Invalid credentials");

        // Create JWT
        var jwtSection = _config.GetSection("Jwt");
        var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtSection["Key"]!));
        var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

        var claims = new[]
        {
            new Claim(ClaimTypes.NameIdentifier, user.Id.ToString()),
            new Claim(ClaimTypes.Email, user.Email),
            new Claim(ClaimTypes.Role, user.Role)
        };

        var token = new JwtSecurityToken(
            issuer: jwtSection["Issuer"],
            audience: jwtSection["Audience"],
            claims: claims,
            expires: DateTime.UtcNow.AddMinutes(double.Parse(jwtSection["ExpiresInMinutes"]!)),
            signingCredentials: creds
        );

        var tokenString = new JwtSecurityTokenHandler().WriteToken(token);

        return Ok(new
        {
            token = tokenString,
            user = new { user.Id, user.Email, user.Role }
        });
    }

    [HttpGet("profile")]
    [Authorize]
    public IActionResult GetProfile()
    {
        var userId = User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
        var email = User.FindFirst(ClaimTypes.Email)?.Value;
        var role = User.FindFirst(ClaimTypes.Role)?.Value;

        return Ok(new
        {
            id = userId,
            email,
            role
        });
    }

    [HttpGet("admin/test")]
    [Authorize(Roles = "admin")]
    public IActionResult AdminOnlyTest()
    {
        return Ok("You are an admin! 🎉");
    }
}
