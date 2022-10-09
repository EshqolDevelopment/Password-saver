import datetime
import os.path

from kivy.clock import mainthread
from kivy4 import *

from kivymd.uix.button import MDFlatButton, MDRaisedButton
from kivymd.uix.dialog import MDDialog
from kivymd.uix.list import TwoLineAvatarIconListItem, IconLeftWidget, IconRightWidget

from encryption import AESCipher, argon2_hash, argon2_verify
from package import *
import pwnedpasswords
import random
from pathlib import Path
from password_strength import PasswordStats

db = init()

pre = '''
<Content>
    orientation: "vertical"
    spacing: "12dp"
    size_hint_y: None
    height: "130dp"
    
    Screen:
        MDTextField:
            id: label_
            hint_text: "Label your password"
            size_hint_x: 0.4
            on_text_validate: app.name_validate()
            pos_hint: {"center_x": 0.2, "center_y": 0.7}
            
        MDTextField:
            id: password_
            hint_text: "Password"
            size_hint_x: 0.4
            on_text_validate: app.add_()
            on_text: app.check_if_twice(self.text)
            pos_hint: {"center_x": 0.2, "center_y": 0.15}
            on_text: app.check_password_strength(self.text)

                
        MDLabel:
            text: "Strength: "
            pos_hint: {"center_x": 0.97, "center_y": 0.15}
        
        
        MDLabel:
            id: strength
            text: "Very week"
            pos_hint: {"x": 0.62, "center_y": 0.15}
            color: 1, 0, 0, 1
            
            
        Text:
            id: warning
            text: "For better security don't use the same password twice"
            font_size: 14
            opacity: 0
            x, y = 0.5, 1
            color: 1, 0.3, 0, 1
            
        
        MDIconButton:
            icon: "cube-outline"
            pos_hint: {"x": 0, "center_y": -0.2}
            on_press: app.generate_password()
    
        MDSlider:
            id: slider
            value: 10
            min: 8
            max: 15
            pos_hint: {"x": 0.1, "center_y": -0.2}
            size_hint_x: 0.4
            size_hint_y: 0.15
            color: (0.5, 1, 0, 1)
            step: 1
            on_value: app.slider_change(self)
            
            
            
<Content1>
    orientation: "vertical"
    spacing: "10dp"
    size_hint_y: None
    height: "100dp"


    Screen:
        MDTextField:
            id: password
            hint_text: "Password"
            size_hint_x: 0.5
            on_text_validate: app.password_pwned()
            password: True
            pos_hint: {"center_x": 0.45, "center_y": 0.7}
            
            
        MDIconButton:
            id: eye
            icon: "eye-off"
            on_press: app.show_password1()
            pos_hint: {"x": 0.72, "center_y": 0.7}
          
                    
        Text:
            id: text
            text: ""
            font_size: 18
            pos_hint: {"x": 0, "center_y": 0.27}
            
        
        BtnIcon:
            icon: "download"
            text: "Generate Report"
            x, y = 0.15, -0.25
            md_bg_color: 0, 0.6, 1, 1
            on_release: app.download_report()

        
'''

kiv = '''
Screen:
    name: 'login'
    
    Text: 
        id: title
        text: 'Login to Password Saver Pro'
        x,y = 0.5, 0.82
        font_size: 26
        
    Text:
        text: 'Enter your email address'
        x, y = 0.5, 0.67
    
    Input:
        id: email
        x, y = 0.5, 0.6
        hint_text: "email"
        on_text_validate: app.validate_email()
    
    Text:
        text: "Enter your password"
        x, y = 0.5, 0.47
    
    Input:
        id: password
        x, y = 0.5, 0.4
        hint_text: "password"
        on_text_validate: app.on_validate()
        password: True
    
    MDIconButton:
        id: eye
        icon: "eye-off"
        x, y = 0.72, 0.4
        on_press: app.show_password()
        
    BtnIcon:
        x, y = 0.7, 0.22
        text: "     Log In"
        icon: 'login'
        size_hint: 0.3, 0.06
        on_release: app.login(email.text.strip(), password.text.strip())
     
    BtnIcon:
        x, y = 0.3, 0.22
        text: "     Sign Up"
        icon: 'account-plus'
        size_hint: 0.3, 0.06
        on_release: app.create(email.text.strip(), password.text.strip())
        
    Check:
        id: remember
        x, y = 0.75, 0.11
    
    Text:
        x, y = 0.44, 0.11
        text: "Remember my password"
        font_size: 15
    
    
Screen:
    name: 'home'
    BoxLayout:
        orientation: "vertical"
        spacing: "10dp"
        id: mdcard
        pos_hint: {"center_x": 0.5, "center_y": 0.4}
        padding: 15
        ScrollView:
            MDList:
                id: container
                
    CircleIcon:
        icon: "plus"
        x, y = 0.93, 0.1
        on_press: app.popup()  
        
    BtnIcon:
        text: "Have I Been Pwned?"
        icon: "lock-check-outline"
        x, y = 0.85, 0.82 
        on_press: app.pwned_popup()
    
    
    
'''


class App(Kivy4):
    ref = None
    pas = None
    username = None
    dialog = None
    dialog123 = None
    global_i = None
    global_name = None
    dialog1 = None
    passwords = set()
    names = set()
    name_to_pass = {}
    happen = False

    def on_start(self):
        remember = self.get_file("remember", create_file_if_not_exist=True, default="False")
        if remember == "True":
            self.root.ids.remember.active = True
            self.root.ids.password.text = self.get_file("password")

        self.root.ids.email.text = self.get_file("email", '', create_file_if_not_exist=True)

    def a(self):
        item = TwoLineAvatarIconListItem(text="Here you can see all your passwords and add new ones.",
                                         secondary_text="Press on the + icon to add new passwords.")

        item.add_widget(IconLeftWidget(icon="key"))
        self.root.ids.container.add_widget(item)
        self.add_passwords()

    def incorrect(self, txt='Incorrect email or password'):
        self.root.ids.title.text = txt

    @thread
    def create(self, username, pas):
        if self.happen:
            return
        self.happen = True

        try:
            self.root.ids.title.text = 'Authentication in process...'
            if not self.isNew(username):
                self.incorrect('User already exist')
            else:
                db.collection('Root').document(username).set({'password_for_encryption': argon2_hash(pas)})
                self.ref = db.collection('Root').document(username)
                self.pas = pas
                self.main_screen(pas, username)

        except Exception:
            self.incorrect()

        self.happen = False

    @thread
    def login(self, username, pas):
        if self.happen:
            return
        self.happen = True
        try:
            self.root.ids.title.text = 'Authentication in process...'
            ref = db.collection('Root').document(username)
            aragon_password = ref.get().to_dict()['password_for_encryption']

            if argon2_verify(aragon_password, pas):
                self.pas = pas
                self.ref = db.collection('Root').document(username)
                self.main_screen(pas, username)
            else:
                self.incorrect()

        except Exception:
            self.incorrect()

        self.happen = False

    def isLogin(self):
        return None not in [self.ref, self.pas]

    def add(self, name, password):
        if len(password) > 50 or len(name) > 50:
            return False

        if not self.isLogin():
            return False

        try:
            self.ref.update({base64.b16encode(name.encode()).decode(): AESCipher(self.pas).encrypt(password).decode()})
            return True

        except Exception:
            return False

    @mainthread
    def main_screen(self, password, email):
        self.screen_positions([900, 600], [900, 600], center=True)
        self.root.ids.screen_manager.current = 'home'
        self.a()

        if self.root.ids.remember.active:
            self.set_file("remember", "True")
            self.set_file("password", password)
        else:
            self.set_file("remember", "False")

        self.set_file("email", email)

    def popup(self):
        if not self.dialog:
            self.dialog = MDDialog(title="Save your password", type="custom", content_cls=Content(),
                                   buttons=[
                                       MDFlatButton(text="CANCEL", theme_text_color="Custom",
                                                    text_color=self.theme_cls.primary_color,
                                                    on_press=lambda x: self.dismiss()),
                                       MDFlatButton(text="OK", theme_text_color="Custom",
                                                    text_color=self.theme_cls.primary_color,
                                                    on_press=lambda x: threading.Thread(target=lambda: self.add_(),
                                                                                        daemon=True).start())])

        self.dialog.open()
        self.dialog.content_cls.ids.label_.text = ''
        self.dialog.content_cls.ids.password_.text = ''

    def dismiss(self):
        self.dialog.dismiss()

    def dismiss123(self):
        self.dialog123.dismiss()

    def add_(self):
        name = self.dialog.content_cls.ids.label_.text
        password = self.dialog.content_cls.ids.password_.text

        if name in self.names:
            self.snack("You can't give two different passwords the same name")
        elif not (password and name):
            self.snack("Please fill in all the required fields")
        else:
            if self.add(name, password):
                self.dismiss()
                self.snack("Added successfully")
                self.add_pass(base64.b16encode(name.encode()).decode(), password)
            else:
                self.snack("We could not save your password due to an unexpected error", button_text="Try Again",
                           func=self.add_)

    def add_pass(self, key, password):
        self.passwords.add(password)
        self.names.add(base64.b16decode(key).decode())
        self.name_to_pass[base64.b16decode(key).decode()] = password

        item = TwoLineAvatarIconListItem(text=' ' * 15 + base64.b16decode(key).decode(),
                                         secondary_text=' ' * 15 + '*' * len(password))
        z = IconLeftWidget(icon="eye-off", on_press=lambda x: self.show(item, z, password))

        item.add_widget(z)
        item.add_widget(IconRightWidget(icon="delete-outline", on_press=lambda x: self.show_alert_dialog(item, key)))
        item.add_widget(IconLeftWidget(icon="content-copy", on_press=lambda x, y=password: self.copy(y)))

        self.root.ids.container.add_widget(item)

    @staticmethod
    def isNew(username):
        return db.collection('Root').document(username).get().to_dict() is None

    @thread
    def add_passwords(self):
        data = self.ref.get().to_dict()
        data.pop('password_for_encryption')
        for key in data:
            password = AESCipher(self.pas).decrypt(data[key].encode())
            self.add_pass(key, password)

    @staticmethod
    def show(item, z, password):
        if z.icon == "eye-off":
            z.icon = "eye"
            item.secondary_text = ' ' * 15 + password
        else:
            z.icon = "eye-off"
            item.secondary_text = ' ' * 15 + '*' * len(password)

    def delete(self):
        self.root.ids.container.remove_widget(self.global_i)
        self.ref.update({self.global_name: firestore.DELETE_FIELD})

        name = base64.b16decode(self.global_name).decode()
        self.names.remove(name)
        self.passwords.remove(self.name_to_pass[name])

        self.dismiss123()

    def copy(self, p):
        pyperclip.copy(p)
        self.snack('Copied successfully')

    def show_alert_dialog(self, i, name):
        self.global_i = i
        self.global_name = name

        color = "000000"
        if self.is_dark_mode():
            color = "ffffff"

        self.dialog123 = MDDialog(text=f"[color={color}]Are you sure you want to delete this password?[/color]",
                                  buttons=[
                                      MDFlatButton(text="NO", theme_text_color="Custom",
                                                   text_color=self.theme_cls.primary_color,
                                                   on_press=lambda *args: self.dismiss123()),
                                      MDFlatButton(text="YES", theme_text_color="Custom",
                                                   text_color=self.theme_cls.primary_color,
                                                   on_press=lambda *args: self.delete())])
        self.dialog123.open()

    def on_validate(self):
        email = self.root.ids.email.text
        password = self.root.ids.password.text

        if email and password:
            self.login(email, password)

    def validate_email(self):
        self.root.ids.password.focus = True

    def name_validate(self):
        self.dialog.content_cls.ids.password_.focus = True

    def check_if_twice(self, password):
        if password in self.passwords:
            self.dialog.content_cls.ids.warning.opacity = 1
        else:
            self.dialog.content_cls.ids.warning.opacity = 0

    def show_password(self):
        password_mode = self.root.ids.password.password
        if password_mode:
            self.root.ids.password.password = False
            self.root.ids.eye.icon = "eye"
        else:
            self.root.ids.password.password = True
            self.root.ids.eye.icon = "eye-off"

    def show_password1(self):
        password_mode = self.dialog1.content_cls.ids.password.password
        if password_mode:
            self.dialog1.content_cls.ids.password.password = False
            self.dialog1.content_cls.ids.eye.icon = "eye"
        else:
            self.dialog1.content_cls.ids.password.password = True
            self.dialog1.content_cls.ids.eye.icon = "eye-off"

    def check_password_strength(self, password):
        if not password:
            strength = 0
        else:
            stats = PasswordStats(password)
            strength = stats.strength() + 0.1

        if strength < 0.2:
            st_strength = "Very week"
            color = (1, 0, 0, 1)
        elif strength < 0.4:
            st_strength = "Week"
            color = (255 / 256, 100 / 256, 0, 1)
        elif strength < 0.5:
            st_strength = "Moderate"
            color = (255 / 256, 170 / 256, 0, 1)
        elif strength < 0.7:
            st_strength = "Strong"
            color = (0, 1, 0, 1)
        else:
            st_strength = "Very strong"
            color = (37 / 256, 176 / 256, 0, 1)

        self.dialog.content_cls.ids.strength.text = st_strength
        self.dialog.content_cls.ids.strength.color = color

    def slider_change(self, slider):
        value = slider.value
        if value <= 9:
            slider.color = (1, 0.75, 0, 1)
        elif value < 12:
            slider.color = (0.5, 1, 0, 1)
        else:
            slider.color = (37 / 256, 176 / 256, 0, 1)

    def generate_password(self):
        value = self.dialog.content_cls.ids.slider.value
        self.dialog.content_cls.ids.password_.text = self.get_random_string(value)

    @staticmethod
    def get_random_string(length):
        letters = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ!$%&~#*"
        result_str = ''.join(random.choice(letters) for _ in range(length))
        return result_str

    def pwned_popup(self):
        self.dialog1 = MDDialog(title="Check if your password is in a data breach", type="custom",
                                content_cls=Content1(),
                                buttons=[
                                    MDFlatButton(text="CANCEL", theme_text_color="Custom",
                                                 text_color=self.theme_cls.primary_color,
                                                 on_press=lambda x: self.dialog1.dismiss()),
                                    MDRaisedButton(text="CHECK",
                                                   on_press=lambda x: threading.Thread(
                                                       target=lambda: self.password_pwned(),
                                                       daemon=True).start())])

        self.dialog1.open()

    def password_pwned(self):
        password = self.dialog1.content_cls.ids.password.text

        times_seen = pwnedpasswords.check(password, plain_text=True)

        if times_seen == 0:
            self.dialog1.content_cls.ids.text.text = "Good news — no pwnage found!"
            self.dialog1.content_cls.ids.text.color = (0, 1, 0, 1)
        else:
            self.dialog1.content_cls.ids.text.text = "This password has been seen " + format(times_seen,
                                                                                             ",") + " times before"
            self.dialog1.content_cls.ids.text.color = (1, 0, 0, 1)

    @thread
    def download_report(self):
        string = ""

        for password in self.passwords:
            times_seen = pwnedpasswords.check(password, plain_text=True)
            name = self.find_name(password)

            pas = password[:3] + "*" * (len(password) - 3)

            if times_seen == 0:
                string += f"{name} - {pas} | Good news — no pwnage found!\n"
            else:
                string += f"{name} - {pas} | This password has been seen " + format(times_seen, ",") + " times before\n"

        downloads_path = str(Path.home() / "Downloads")
        path = f"{downloads_path}/passwords report {datetime.date.today()}.txt"
        with open(path, "w") as f:
            f.write(string)

        os.startfile(path)

    def find_name(self, password):
        for key in self.name_to_pass:
            if self.name_to_pass[key] == password:
                return key
        return "Not Found Error"


if __name__ == '__main__':
    App(app_name='Password Saver Pro', toolbar=True, main_color='Orange', string=kiv,
        screen_size=[450, 650], pre_string=pre, icon='img.png').run()
