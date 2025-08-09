include "pages/page.wl"

let posts = $query("SELECT title, content FROM Posts WHERE id=?", $post_id)
let post = posts[0]

let style =
    <style>
    </style>

let main =
    <main>
        <h3>\post.title</h3>
        <p>\post.content</p>
    </main>

page(post.title, $login_user_id, style, main)