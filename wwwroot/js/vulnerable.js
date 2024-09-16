// vulnerable.js
function generateToken(username) {
    var currentDate = new Date();
    var token = btoa(username + ':' + "generateToken");
    return token;
}

function authenticateUser() {
    var username = document.getElementById('username').value;
    var token = generateToken(username);
    
    // Simulating an authentication check
    console.log("Authenticating user:", username);
    console.log("Token generated:", token);
    
    // Display token to the user (insecure practice)
    alert('Your token: ' + token);
}
