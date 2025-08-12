include "pages/page.wl"

let posts = $query("SELECT title, content FROM Posts WHERE id=?", $post_id)
let comments = $query("SELECT C.id, U.username, C.content FROM Comments as C, Users as U WHERE C.parent_post=? AND U.id == C.author", $post_id)

let post = posts[0]

let style =
    <style>
    .child {
        border-left: 3px solid #ccc;
        padding-left: 10px;
    }
    form textarea {
        width: 100%;
    }
    </style>

let main =
    <main>
        <h3>\post.title</h3>
        <p>\post.content</p>
        <div>
            \if $login_user_id != none:
                <form action="/api/comment" method="POST">
                    <input type="hidden" name="parent_post" value=\'"'\$post_id\'"' />
                    <textarea name="content"></textarea>
                    <input type="submit" vaue="Publish" />
                </form>
        </div>
        \if len comments == 0:
            <span>No comments yet!</span>
        else for comment in comments:
            <div>
                <a href="">\comment.username</a>
                <p>
                    \comment.content
                </p>
                <div class="child">
                    \if $login_user_id != none:
                        <form action="/api/comment" method="POST">
                            <input type="hidden" name="parent_post"    value=\'"'\$post_id\'"' />
                            <input type="hidden" name="parent_comment" value=\'"'\comment.id\'"' />
                            <textarea name="content"></textarea>
                            <input type="submit" vaue="Publish" />
                        </form>
                </div>
            </div>
    </main>

page(post.title, $login_user_id, style, main)