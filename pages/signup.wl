include "pages/page.wl"
include "pages/login_and_signup_style.wl"

let main =
    <main>
        <span>Welcome!</span>
        <form action="/api/signup" method="POST">
            <input type="text"     name="username"  placeholder="username"        />
            <input type="email"    name="email"     placeholder="email"           />
            <input type="password" name="password1" placeholder="password"        />
            <input type="password" name="password2" placeholder="repeat password" />
            <input type="submit"   value="Sign-Up"  />
            <div class="form-links">
                <a href="">forgot password?</a>
                |
                <a href="">already have an account?</a>
            </div>
        </form>
    </main>

page("Log-In", none, style, main)
