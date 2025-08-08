include "pages/page.wl"

let style =
    <style>
    </style>

let main =
    <main>
        <form action="api/post" method="POST">
            <input type="text" name="title" />
            <textarea name="content"></textarea>
            <input type="submit" value="Publish" />
        </form>
    </main>

page("Write Post", $login_user_id, style, main)
