include "pages/page.wl"

let posts = [
    { title: "Show HN: Kitten TTS - 25MB CPU-Only, Open-Source TTS Model",   date: "3 hours ago",    num_comments: 127, link: "https://github.com/KittenML/KittenTTS" },
    { title: "Open models by OpenAI",                                        date: "15 hours ago",   num_comments: 651, link: "https://openai.com/open-models/"       },
    { title: "Anthropic rejects the main developer of the library they use", date: "40 minutes ago", num_comments: 437, link: "https://grell.dev/blog/ai_rejection"   }
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

let main =
    <main>
        \for post in posts:
            <div class="item">
                <div>
                    <a href=post.link>\post.title</a>
                </div>
                <div>
                    <span>\post.date</span> | <span><a href="/thread">\post.num_comments comments</a></span>
                </div>
            </div>
    </main>

page("Index", $login_user_id, style, main)
