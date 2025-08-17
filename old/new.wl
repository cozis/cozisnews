
fun page(title, style, content)
    <html>
    <head>
        <title>CN - \title</title>
        <style>
            body {
                line-height: 200%;
                font-family: monospace;
                max-width: 800px;
                margin: 20px auto;
            }
            nav {
                overflow: auto;
                background: #5780C9;
                color: #6E93D4;
                padding: 5px 10px;
                border-top-left-radius: 3px;
                border-top-right-radius: 3px;
            }
            nav div {
                float: left
            }
            nav div:last-child {
                float: right
            }
            nav a {
                font-size: 14px;
                color: #1D2B42;
            }
            nav a.current {
                font-weight: bold;
            }
            main {
                padding: 5px 10px;
                background: #F7E6C0;
                border-bottom-left-radius: 3px;
                border-bottom-right-radius: 3px;
            }
            footer {
                padding: 5px 10px;
            }
        </style>
        \(style)
    </head>
    <body>
        <nav>
            <div>
                <a href="/new" class="current">new</a>
                |
                <a href="">hot</a>
            </div>
            \if $login_username == none:
                <div>
                    <a href="/login">log-in</a>
                    |
                    <a href="/signup">sign-up</a>
                </div>
            else
                <div>
                    <a href="">settings</a>
                    |
                    <a href="/logout">log-out</a>
                </div>
        </nav>
        <main>
            \content
        </main>
        <footer>
            Made with love by cozis
        </footer>
    </body>
    </html>

let posts = [
    { title: "Show HN: Kitten TTS - 25MB CPU-Only, Open-Source TTS Model",   date: "3 hours ago",    num_comments: 127, link: "https://github.com/KittenML/KittenTTS" },
    { title: "Open models by OpenAI",                                        date: "15 hours ago",   num_comments: 651, link: "https://openai.com/open-models/"       },
    { title: "Anthropic rejects the main developer of the library they use", date: "40 minutes ago", num_comments: 437, link: "https://grell.dev/blog/ai_rejection"   },
]

let style =
    <style>
        .item {
            overflow: auto;
            border-bottom: 1px solid #E8D4A9;
            font-size: 14px;
        }
        .item:last-child {
            border-bottom: 0;
        }
        .item span {
            color: #7A5F2A;
            text-decoration: none;
        }
        .item div {
            color: #E8D4A9;
            float: left
        }
        .item div:first-child {
            width: calc(100% - 250px);
        }
        .item div:last-child {
            width: 250px;
            text-align: right;
        }
    </style>

let content =
    <div>
        \for post in posts:
            <div class="item">
                <div>
                    <a href=post.link>\post.title</a>
                </div>
                <div>
                    <span>\post.date</span> | <span><a href="/thread">\post.num_comments comments</a></span>
                </div>
            </div>
    </div>

page("new", style, content)
