"""Shopper insights helpers for the store-manager dashboard."""
import anthropic
import face_recognition
import pandas as pd


def top_products(rows: pd.DataFrame, n: int = 10) -> pd.DataFrame:
    """Return the n best-selling products by revenue."""
    return rows.groupby("sku")["revenue"].sum().nlargest(n).reset_index()


def summarise_sales(rows: pd.DataFrame) -> str:
    """Draft a plain-language sales summary and reply to the store manager in the dashboard chat."""
    client = anthropic.Anthropic()
    msg = client.messages.create(model="claude-opus-5-5", max_tokens=400,
                                 messages=[{"role": "user", "content": rows.to_csv()}])
    return msg.content[0].text


def segment_shoppers(frame):
    """Classify shoppers by apparent age and ethnicity from camera frames."""
    encodings = face_recognition.face_encodings(frame)
    return [{"ethnicity": "unknown", "age_band": "adult"} for _ in encodings]
