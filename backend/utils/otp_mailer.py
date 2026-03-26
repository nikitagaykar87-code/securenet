import random
from flask_mail import Message
from flask import current_app

otp_store = {}

def generate_otp():
    return str(random.randint(100000, 999999))

def send_otp(email):
    otp = generate_otp()
    otp_store[email] = otp

    mail = current_app.extensions["mail"]

    msg = Message(
        subject="SecureNet Verification Code",
        sender=current_app.config["MAIL_USERNAME"],
        recipients=[email]
    )

    # ✅ PROFESSIONAL HTML EMAIL
    msg.html = f"""
    <div style="font-family: Arial, Helvetica, sans-serif; 
                background-color:#f4f6f8; 
                padding:30px;">

        <div style="max-width:520px;
                    margin:auto;
                    background:#ffffff;
                    border-radius:8px;
                    padding:30px;
                    box-shadow:0 4px 12px rgba(0,0,0,0.08);">

            <h2 style="color:#0b5ed7;
                       margin-bottom:10px;">
                SecureNet Verification
            </h2>

            <p style="color:#333; font-size:14px;">
                Dear User,
            </p>

            <p style="color:#333; font-size:14px;">
                We received a request to verify your email address.
                Please use the verification code below to continue.
            </p>

            <div style="margin:25px 0;
                        text-align:center;">
                <span style="display:inline-block;
                             font-size:26px;
                             letter-spacing:6px;
                             font-weight:bold;
                             color:#0b5ed7;
                             padding:12px 20px;
                             border:1px dashed #0b5ed7;
                             border-radius:6px;">
                    {otp}
                </span>
            </div>

            <p style="color:#333; font-size:14px;">
                This code is valid for <b>5 minutes</b>.
            </p>

            <p style="color:#666; font-size:13px;">
                For your security, please do not share this code with anyone.
                If you did not request this verification, you may safely ignore this email.
            </p>

            <hr style="margin:25px 0; border:none; border-top:1px solid #e0e0e0;">

            <p style="color:#666; font-size:13px;">
                Regards,<br>
                <b>SecureNet Security Team</b>
            </p>

        </div>
    </div>
    """

    mail.send(msg)