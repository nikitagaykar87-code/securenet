import requests
import xml.etree.ElementTree as ET
import sqlite3
from flask import Blueprint, jsonify
from datetime import datetime, timedelta
from config import DATABASE

news_bp = Blueprint("news_bp", __name__)

def db():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn

def fetch_cyber_news():
    """Fetches real-time cyber news from Google News RSS for India."""
    url = "https://news.google.com/rss/search?q=cybersecurity+india&hl=en-IN&gl=IN&ceid=IN:en"
    
    try:
        response = requests.get(url, timeout=10)
        if response.status_code != 200:
            return []
            
        root = ET.fromstring(response.content)
        articles = []
        
        for item in root.findall(".//item"):
            title = item.find("title").text if item.find("title") is not None else "No Title"
            link = item.find("link").text if item.find("link") is not None else "#"
            source = item.find("source").text if item.find("source") is not None else "Unknown"
            pub_date = item.find("pubDate").text if item.find("pubDate") is not None else ""
            description = item.find("description").text if item.find("description") is not None else ""
            
            # Simple heuristic for image (Google News RSS doesn't provide direct image URL in standard tags)
            # We'll use a placeholder or random cybersecurity image for UI
            image_url = f"https://images.unsplash.com/photo-1550751827-4bd374c3f58b?auto=format&fit=crop&q=80&w=800"
            
            articles.append({
                "title": title,
                "link": link,
                "source": source,
                "pub_date": pub_date,
                "description": description,
                "image_url": image_url
            })
            
        return articles
    except Exception as e:
        print(f"Error fetching news: {e}")
        return []

def update_news_cache():
    """Updates the database with fresh news and returns the count."""
    articles = fetch_cyber_news()
    if not articles:
        return 0
        
    conn = db()
    cur = conn.cursor()
    
    try:
        # Clear old news (optional, or just keep it)
        # cur.execute("DELETE FROM cyber_news")
        
        for a in articles:
            cur.execute("""
                INSERT OR IGNORE INTO cyber_news (title, link, source, pub_date, description, image_url)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (a['title'], a['link'], a['source'], a['pub_date'], a['description'], a['image_url']))
            
        conn.commit()
        return len(articles)
    except Exception as e:
        print(f"Error caching news: {e}")
        return 0
    finally:
        conn.close()

@news_bp.route("/news", methods=["GET"])
def get_news():
    """Returns cached news if fresh, otherwise fetches and returns."""
    conn = db()
    cur = conn.cursor()
    
    try:
        # Check if we have any news and how old it is
        cur.execute("SELECT fetched_at FROM cyber_news ORDER BY fetched_at DESC LIMIT 1")
        last_fetch = cur.fetchone()
        
        should_refresh = True
        if last_fetch:
            last_fetch_time = datetime.strptime(last_fetch[0], "%Y-%m-%d %H:%M:%S")
            if datetime.now() - last_fetch_time < timedelta(hours=6):
                should_refresh = False
                
        if should_refresh:
            update_news_cache()
            
        # Get top 20 news
        cur.execute("SELECT * FROM cyber_news ORDER BY id DESC LIMIT 20")
        rows = cur.fetchall()
        news_list = [dict(row) for row in rows]
        
        return jsonify({"success": True, "news": news_list})
        
    except Exception as e:
        return jsonify({"success": False, "message": str(e)}), 500
    finally:
        conn.close()
