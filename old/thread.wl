<html>
<head>
    <meta charset="utf-8" />
    <title>cozis news - thread</title>
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
        
        /* Thread styles */
        .thread-header {
            padding: 15px 0;
            border-bottom: 2px solid #E8D4A9;
            margin-bottom: 20px;
        }
        .thread-title {
            font-size: 16px;
            font-weight: bold;
            margin-bottom: 8px;
        }
        .thread-title a {
            color: #1D2B42;
            text-decoration: none;
        }
        .thread-title a:hover {
            text-decoration: underline;
        }
        .thread-meta {
            font-size: 12px;
            color: #7A5F2A;
            margin-bottom: 10px;
        }
        .thread-meta a {
            color: #7A5F2A;
        }
        .thread-text {
            font-size: 14px;
            color: #1D2B42;
            line-height: 160%;
            margin-bottom: 10px;
        }
        .thread-actions {
            font-size: 12px;
        }
        .thread-actions a {
            color: #7A5F2A;
            margin-right: 10px;
        }
        
        /* Comment styles */
        .comment {
            margin-bottom: 15px;
            border-left: 1px solid #E8D4A9;
            padding-left: 10px;
        }
        .comment.level-0 { margin-left: 0px; }
        .comment.level-1 { margin-left: 20px; }
        .comment.level-2 { margin-left: 40px; }
        .comment.level-3 { margin-left: 60px; }
        .comment.level-4 { margin-left: 80px; }
        
        .comment-meta {
            font-size: 11px;
            color: #7A5F2A;
            margin-bottom: 5px;
        }
        .comment-meta a {
            color: #7A5F2A;
        }
        .comment-text {
            font-size: 13px;
            color: #1D2B42;
            line-height: 150%;
            margin-bottom: 5px;
        }
        .comment-actions {
            font-size: 11px;
        }
        .comment-actions a {
            color: #7A5F2A;
            margin-right: 8px;
        }
        .comment-actions a:hover {
            color: #1D2B42;
        }
        
        .vote-buttons {
            float: left;
            width: 15px;
            margin-right: 8px;
            font-size: 10px;
            text-align: center;
        }
        .vote-buttons a {
            display: block;
            color: #7A5F2A;
            text-decoration: none;
            line-height: 100%;
        }
        .vote-buttons a:hover {
            color: #1D2B42;
        }
        
        .comment-content {
            margin-left: 23px;
        }
        
        .add-comment {
            margin: 20px 0;
            padding: 15px;
            background: #E8D4A9;
            border-radius: 3px;
            border: 1px solid #D4C298;
        }
        .add-comment textarea {
            width: 100%;
            height: 80px;
            font-family: monospace;
            font-size: 12px;
            background: #F7E6C0;
            border: 1px solid #D4C298;
            border-radius: 3px;
            padding: 8px;
            box-sizing: border-box;
            resize: vertical;
        }
        .add-comment button {
            background: #5780C9;
            color: #F7E6C0;
            border: none;
            border-radius: 3px;
            padding: 6px 12px;
            font-family: monospace;
            font-size: 12px;
            cursor: pointer;
            margin-top: 8px;
        }
        .add-comment button:hover {
            background: #1D2B42;
        }
        
        .collapsed {
            color: #7A5F2A;
            font-size: 11px;
            cursor: pointer;
        }
        .collapsed:hover {
            color: #1D2B42;
        }
    </style>
</head>
<body>
    <nav>
        <div>
            <a href="/new" class="current">new</a>
            |
            <a href="">hot</a>
        </div>
        <div>
            <a href="">settings</a>
            |
            <a href="/login">log-out</a>
        </div>
    </nav>
    <main>
        <div class="thread-header">
            <div class="thread-title">
                <a href="https://github.com/KittenML/KittenTTS">Show HN: Kitten TTS - 25MB CPU-Only, Open-Source TTS Model</a>
            </div>
            <div class="thread-meta">
                submitted 3 hours ago by <a href="">kittenlover42</a> | <a href="">127 comments</a>
            </div>
            <div class="thread-text">
                Hey HN! I've been working on Kitten TTS for the past 6 months - a tiny text-to-speech model that runs entirely on CPU. At just 25MB, it's perfect for embedded applications and privacy-focused projects where you don't want to send text to external services.
                <br/><br/>
                The model is trained on a diverse dataset and supports multiple languages. Performance is surprisingly good for the size - would love to hear your thoughts!
            </div>
            <div class="thread-actions">
                <a href="">reply</a>
            </div>
        </div>
        
        <div class="add-comment">
            <textarea placeholder="Add a comment..."></textarea>
            <button>add comment</button>
        </div>
        
        <div class="comment level-0">
            <div class="vote-buttons">
                <a href="">▲</a>
                <a href="">▼</a>
            </div>
            <div class="comment-content">
                <div class="comment-meta">
                    <a href="">techgeek99</a> 2 hours ago
                </div>
                <div class="comment-text">
                    This is incredible! I've been looking for something exactly like this for my IoT project. The fact that it's only 25MB and runs on CPU is a game changer. How does the voice quality compare to larger models?
                </div>
                <div class="comment-actions">
                    <a href="">reply</a> | <a href="">flag</a>
                </div>
            </div>
        </div>
        
        <div class="comment level-1">
            <div class="vote-buttons">
                <a href="">▲</a>
                <a href="">▼</a>
            </div>
            <div class="comment-content">
                <div class="comment-meta">
                    <a href="">kittenlover42</a> 2 hours ago
                </div>
                <div class="comment-text">
                    Thanks! The voice quality is obviously not as good as larger models like Tacotron2 or the commercial APIs, but it's surprisingly decent for most use cases. I'd say it's about 75% of the quality at 1% of the size. Perfect for things like reading notifications aloud or simple voice interfaces.
                </div>
                <div class="comment-actions">
                    <a href="">reply</a> | <a href="">flag</a>
                </div>
            </div>
        </div>
        
        <div class="comment level-2">
            <div class="vote-buttons">
                <a href="">▲</a>
                <a href="">▼</a>
            </div>
            <div class="comment-content">
                <div class="comment-meta">
                    <a href="">embedded_dev</a> 1 hour ago
                </div>
                <div class="comment-text">
                    That sounds perfect for embedded applications! What's the inference speed like on something like a Raspberry Pi?
                </div>
                <div class="comment-actions">
                    <a href="">reply</a> | <a href="">flag</a>
                </div>
            </div>
        </div>
        
        <div class="comment level-0">
            <div class="vote-buttons">
                <a href="">▲</a>
                <a href="">▼</a>
            </div>
            <div class="comment-content">
                <div class="comment-meta">
                    <a href="">ml_researcher</a> 2 hours ago
                </div>
                <div class="comment-text">
                    Very impressive work! I'm curious about the architecture - are you using knowledge distillation from a larger model, or did you train this from scratch? The 25MB constraint must have required some clever optimizations.
                </div>
                <div class="comment-actions">
                    <a href="">reply</a> | <a href="">flag</a>
                </div>
            </div>
        </div>
        
        <div class="comment level-1">
            <div class="vote-buttons">
                <a href="">▲</a>
                <a href="">▼</a>
            </div>
            <div class="comment-content">
                <div class="comment-meta">
                    <a href="">kittenlover42</a> 1 hour ago
                </div>
                <div class="comment-text">
                    Great question! It's a combination approach. I started with a modified Tacotron architecture but with much smaller hidden dimensions, then used knowledge distillation from WaveNet to get the vocoder down to size. Also heavily quantized the weights and used some pruning techniques. Happy to share more technical details if you're interested!
                </div>
                <div class="comment-actions">
                    <a href="">reply</a> | <a href="">flag</a>
                </div>
            </div>
        </div>
        
        <div class="comment level-0">
            <div class="vote-buttons">
                <a href="">▲</a>
                <a href="">▼</a>
            </div>
            <div class="comment-content">
                <div class="comment-meta">
                    <a href="">privacy_advocate</a> 1 hour ago
                </div>
                <div class="comment-text">
                    Love that this runs locally! So tired of having to send my text to Google/Amazon/etc just to get speech synthesis. This is exactly what we need more of in the open source community.
                </div>
                <div class="comment-actions">
                    <a href="">reply</a> | <a href="">flag</a>
                </div>
            </div>
        </div>
        
        <div class="comment level-0">
            <div class="collapsed">
                [5 more comments]
            </div>
        </div>
        
    </main>
    <footer>
        Made with love by cozis
    </footer>
</body>
</html>