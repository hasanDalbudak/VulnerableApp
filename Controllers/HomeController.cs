using System.Diagnostics;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using VulnerableApp.Data;
using VulnerableApp.Models;

namespace VulnerableApp.Controllers;

public class HomeController : Controller
{

    private readonly ApplicationDbContext _context;

    public HomeController(ApplicationDbContext context)
    {
        _context = context;
    }

    public IActionResult Login()
    {
        return View();
    }

    [HttpPost]
    public IActionResult Login(string username, string password)
    {
        var user = _context.Users.FirstOrDefault(u => u.Username == username && u.Password == password);

        if (user != null)
        {
            // Store the user role and username in session
            HttpContext.Session.SetString("Role", user.Role);
            HttpContext.Session.SetString("Username", user.Username);
            return RedirectToAction("Dashboard");
        }

        ViewBag.Message = "Invalid username or password.";
        return View();
    }

    public IActionResult Dashboard()
    {
        var role = HttpContext.Session.GetString("Role");

        if (string.IsNullOrEmpty(role))
        {
            return RedirectToAction("Login");
        }

        // Show dashboard based on role
        return View();
    }

    public IActionResult Logout()
    {
        // Clear the session
        HttpContext.Session.Clear();

        // Redirect to login page or homepage
        return RedirectToAction("Login");
    }

    public IActionResult BruteForce()
    {
        return View();
    }

    [HttpPost]
    public IActionResult BruteForceLogin(string username, string password)
    {
        // Simulating a simple list of users
        var validUsers = new List<User>
    {
        new User { Username = "admin", Password = "adminpass", Role = "admin" },
        new User { Username = "user", Password = "userpass", Role = "user" }
    };

        // Check if the user exists
        var user = validUsers.FirstOrDefault(u => u.Username == username && u.Password == password);

        if (user != null)
        {
            // Simulate successful login
            ViewBag.Message = "Login successful! You are logged in as " + user.Username;
            return View("BruteForce");  // You can redirect to Dashboard or another page here
        }

        // Simulate failed login
        ViewBag.Message = "Invalid credentials. Try again!";
        return View("BruteForce");
    }


    public IActionResult Privacy()
    {
        return View();
    }

    public IActionResult SQLInjection()
    {
        return View();
    }

    [HttpPost]
    public IActionResult SQLInjectionResult(string username)
    {
        // Vulnerable SQL query using string concatenation
        string query = $"SELECT Id, Username, Password, Role FROM Users WHERE Username = '{username}' UNION SELECT 1, Username, Password, Role FROM Users";

        // Log the query to the console for debugging purposes
        Console.WriteLine($"Executing SQL Query: {query}");

        // Execute the query directly using raw SQL (simulating vulnerability)
        var users = _context.Users
            .FromSqlRaw(query)  // FromSqlRaw allows raw SQL queries
            .ToList();

        // Construct a result message that includes Username, Password, and Role for each user
        if (users.Count > 0)
        {
            var result = string.Join("<br/>", users.Select(u => $"Username: {u.Username}, Password: {u.Password}, Role: {u.Role}"));
            ViewBag.Result = $"Users found:<br/>{result}";
        }
        else
        {
            ViewBag.Result = "No users found.";
        }

        return View("SQLInjection");
    }

    public IActionResult XSSDOM()
    {
        return View();
    }

    // Action to display the Stored XSS page with all comments
    public IActionResult XSSStored()
    {
        // Fetch all comments from the database
        var comments = _context.Comments.ToList();
        return View(comments);
    }

    // Action to handle the comment submission
    [HttpPost]
    public IActionResult XSSStored(string username, string content)
    {
        // Save the comment in the database (no sanitization for XSS demonstration)
        var comment = new Comment
        {
            Username = username,
            Content = content
        };

        _context.Comments.Add(comment);
        _context.SaveChanges();

        // Redirect back to the comments page
        return RedirectToAction("XSSStored");
    }

    public IActionResult XSSReflected(string name)
    {
        // Deliberately reflect the user input without sanitization
        ViewBag.Message = $"Hello, {name}";

        return View("XSSReflected");
    }


    [HttpGet]
    public IActionResult CSRF()
    {
        return View();
    }

    [HttpPost]
    public IActionResult CSRF(string password)
    {
        // Log session data for debugging
        Console.WriteLine("Session ID in CSRF action: " + HttpContext.Session.Id);
        Console.WriteLine("Username from session in CSRF action: " + HttpContext.Session.GetString("Username"));

        // Get the username of the currently logged-in user from the session
        var username = HttpContext.Session.GetString("Username");

        if (username != null)
        {
            // Find the user in the database based on the session's username
            var user = _context.Users.FirstOrDefault(u => u.Username == username);

            if (user != null)
            {
                // Update the user's password
                user.Password = password;
                _context.SaveChanges();
                ViewBag.Message = $"Password successfully changed for user: {username}";
            }
            else
            {
                ViewBag.Message = "User not found!";
            }
        }
        else
        {
            ViewBag.Message = "No user is logged in!";
        }

        return View("CSRF");
    }


    public IActionResult TestCredentials()
    {
        return View();
    }

    [HttpPost]
    public IActionResult TestCredentials(string password)
    {
        // Get the logged-in user's username from the session
        var username = HttpContext.Session.GetString("Username");

        if (username != null)
        {
            // Check if the provided password matches the logged-in user's password
            var user = _context.Users.FirstOrDefault(u => u.Username == username && u.Password == password);

            if (user != null)
            {
                ViewBag.Message = $"Credentials are valid for user: {username}";
            }
            else
            {
                ViewBag.Message = "Invalid credentials!";
            }
        }
        else
        {
            ViewBag.Message = "No user is logged in!";
        }

        return View();
    }
    public IActionResult FileUpload()
    {
        return View();
    }

    [HttpPost]
    public IActionResult FileUpload(IFormFile fileUpload)
    {
        if (fileUpload != null && fileUpload.Length > 0)
        {
            var filePath = Path.Combine(Directory.GetCurrentDirectory(), "wwwroot", "uploads", fileUpload.FileName);

            // Ensure the uploads directory exists
            Directory.CreateDirectory(Path.GetDirectoryName(filePath));

            using (var stream = new FileStream(filePath, FileMode.Create))
            {
                fileUpload.CopyTo(stream);
            }

            ViewBag.Message = "File uploaded successfully!";
        }
        else
        {
            ViewBag.Message = "No file was selected for upload.";
        }

        return View();
    }


    public async Task<IActionResult> RemoteFileInclusion(string url)
    {
        if (string.IsNullOrEmpty(url))
        {
            ViewBag.FileContent = "No URL provided.";
            Console.WriteLine("No URL provided.");  // Log to the console
            return View();
        }

        Console.WriteLine($"Attempting to fetch URL: {url}");  // Log the URL

        try
        {
            using (HttpClient client = new HttpClient())
            {
                // Try to fetch content from the remote URL
                string fileContent = await client.GetStringAsync(url);

                // Log the content length for debugging
                Console.WriteLine($"Content fetched successfully. Length: {fileContent.Length}");

                // Display the fetched content on the page
                ViewBag.FileContent = fileContent;
            }
        }
        catch (Exception ex)
        {
            // Log any exceptions
            Console.WriteLine($"Error fetching URL: {ex.Message}");
            ViewBag.FileContent = "Unable to load the requested file.";
        }

        return View();
    }


    public IActionResult LocalFileInclusion(string file)
    {
        // Check if the file parameter is null or empty
        if (string.IsNullOrEmpty(file))
        {
            ViewBag.FileContent = "No file specified.";
            return View();
        }

        // Safe directory where files are located
        string safeDirectory = Path.Combine(Directory.GetCurrentDirectory(), "wwwroot", "files");
        string filePath = Path.Combine(safeDirectory, file);

        // Ensure the file path is within the allowed directory and the file exists
        if (!filePath.StartsWith(safeDirectory) || !System.IO.File.Exists(filePath))
        {
            ViewBag.FileContent = "File not found or access denied!";
            return View();
        }

        // Read the file content and pass it to the view
        ViewBag.FileContent = System.IO.File.ReadAllText(filePath);
        return View();
    }


    public IActionResult CommandInjection()
    {
        return View();
    }

    [HttpPost]
    public IActionResult CommandInjection(string target)
    {
        // Vulnerable to command injection
        // Directly passing user input to the shell command
        string command = $"ping {target}";
        var processInfo = new ProcessStartInfo("cmd.exe", "/c " + command)
        {
            RedirectStandardOutput = true,
            UseShellExecute = false,
            CreateNoWindow = true
        };

        var process = new Process
        {
            StartInfo = processInfo
        };

        process.Start();
        string result = process.StandardOutput.ReadToEnd();
        process.WaitForExit();

        // Pass the result to the view
        ViewBag.Result = result;
        return View();
    }

    public IActionResult OpenRedirect(string redirectUrl)
    {
        // Vulnerable: This redirects the user to the URL provided in the query string without validation
        if (!string.IsNullOrEmpty(redirectUrl))
        {
            return Redirect(redirectUrl);
        }

        // If no redirect URL is provided, just show the form
        return View();
    }


    public IActionResult JavaScript()
    {
        return View();
    }

    [IgnoreAntiforgeryToken]
    public IActionResult InsecureCAPTCHA()
    {
        return View();
    }

    [IgnoreAntiforgeryToken]
    [HttpPost]
    public IActionResult InsecureCAPTCHA(string captchaAnswer, int step, string password_new, string password_conf)
    {
        if (step == 1)
        {
            if (captchaAnswer == "4" && password_new == password_conf)
            {
                ViewBag.HideForm = true;
                ViewBag.Password = password_new;  // Normally, you'd hash this or handle it securely.
                return View();
            }
            else
            {
                ViewBag.Message = "CAPTCHA incorrect or passwords do not match.";
                return View();
            }
        }
        else if (step == 2)
        {
            if (password_new == password_conf)
            {
                // Update the password in the database here
                ViewBag.Message = "Password Changed Successfully.";
            }
            else
            {
                ViewBag.Message = "Passwords did not match.";
            }
        }

        return View();
    }

    public IActionResult WeakSessionId()
    {
        return View();
    }

    [HttpPost]
    public IActionResult GenerateWeakCookie()
    {
        // Generate a weak cookie based on the current time
        DateTime now = DateTime.Now;
        string weakCookieValue = "USER" + now.ToString("yyyyMMddHHmm"); // Predictable pattern

        // Create a cookie and add it to the response
        CookieOptions options = new CookieOptions
        {
            Expires = DateTime.Now.AddMinutes(30), // Cookie expires in 30 minutes
            HttpOnly = false, // Allow visibility in browser inspector for demonstration
        };
        Response.Cookies.Append("WeakCookie", weakCookieValue, options);

        // Pass the cookie value to the view to display
        ViewBag.CookieValue = weakCookieValue;

        return View("WeakSessionId");
    }



    public IActionResult AuthorizationBypass()
    {
        var role = HttpContext.Session.GetString("Role");

        if (role == "admin")
        {
            ViewBag.IsAdmin = true; // Show "View Users" button for admin
        }

        return View();
    }

    public IActionResult ViewUser()
    {
        // This action should be restricted but isn't due to missing access control
        var users = _context.Users.ToList();
        return View(users); // Display all users, regardless of role
    }

    public IActionResult SQLInjectionBlind()
    {
        return View();
    }


    [HttpPost]
    public IActionResult SQLInjectionBlindResult(string username, string password)
    {
        // Vulnerable SQL query that allows blind SQL injection
        string query = $"SELECT * FROM Users WHERE Username = '{username}' AND Password = '{password}'";

        // Log the query to the console for debugging purposes
        Console.WriteLine($"Executing SQL Query: {query}");

        // Execute the query directly using raw SQL (simulating the vulnerability)
        var user = _context.Users
            .FromSqlRaw(query)  // FromSqlRaw allows raw SQL queries
            .FirstOrDefault();

        // Blind SQL behavior: return success or failure without revealing details
        if (user != null)
        {
            ViewBag.Message = "Login successful!";
        }
        else
        {
            ViewBag.Message = "Login failed!";
        }

        return View("SQLInjectionBlind");
    }

    

}

