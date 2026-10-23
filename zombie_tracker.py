import colorsys
import ctypes
from ctypes import wintypes
import json
import math
import os
import re
import socket
import struct
import subprocess
import sys
import threading
import time
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
import urllib.request
import xml.etree.ElementTree as ET
from PIL import Image, ImageTk

APP_VERSION = "1.0.10"

def resource_path(relative_path):
  try:
    base_path = sys._MEIPASS
  except Exception:
    base_path = os.path.abspath(".")
  return os.path.join(base_path, relative_path)

TH32CS_SNAPPROCESS = 0x00000002
TH32CS_SNAPMODULE = 0x00000008
TH32CS_SNAPMODULE32 = 0x00000010
PROCESS_VM_READ = 0x0010
PROCESS_QUERY_INFORMATION = 0x0400


class PROCESSENTRY32(ctypes.Structure):
  _fields_ = [
      ("dwSize", wintypes.DWORD),
      ("cntUsage", wintypes.DWORD),
      ("th32ProcessID", wintypes.DWORD),
      ("th32DefaultHeapID", ctypes.POINTER(ctypes.c_ulong)),
      ("th32ModuleID", wintypes.DWORD),
      ("cntThreads", wintypes.DWORD),
      ("th32ParentProcessID", wintypes.DWORD),
      ("pcPriClassBase", ctypes.c_long),
      ("dwFlags", wintypes.DWORD),
      ("szExeFile", ctypes.c_char * 260),
  ]


class MODULEENTRY32(ctypes.Structure):
  _fields_ = [
      ("dwSize", wintypes.DWORD),
      ("th32ModuleID", wintypes.DWORD),
      ("th32ProcessID", wintypes.DWORD),
      ("GlblcntUsage", wintypes.DWORD),
      ("ProccntcalcUsage", wintypes.DWORD),
      ("modBaseAddr", ctypes.POINTER(ctypes.c_byte)),
      ("modBaseSize", wintypes.DWORD),
      ("hModule", wintypes.HMODULE),
      ("szModule", ctypes.c_char * 256),
      ("szExePath", ctypes.c_char * 260),
  ]

class MemoryReader:

  def __init__(self, process_name="blackops3.exe"):
    self.process_name = process_name
    self.pid = None
    self.h_process = None
    self.kernel32 = ctypes.windll.kernel32

  def attach(self):
    self.close()

    hSnap = self.kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
    if hSnap == -1:
      return False

    pe32 = PROCESSENTRY32()
    pe32.dwSize = ctypes.sizeof(PROCESSENTRY32)

    if self.kernel32.Process32First(hSnap, ctypes.byref(pe32)):
      while True:
        try:
          exe_name = (
              pe32.szExeFile.decode("utf-8", errors="ignore")
              .split("\x00")[0]
              .strip()
              .lower()
          )
        except Exception:
          exe_name = ""

        if exe_name == self.process_name.lower():
          self.pid = pe32.th32ProcessID
          
          ACCESS_RIGHTS = PROCESS_VM_READ | PROCESS_QUERY_INFORMATION
          
          # ADD THIS LINE:
          print(f"[DEBUG] Requesting OpenProcess with access mask: 0x{ACCESS_RIGHTS:X}")
          
          self.h_process = self.kernel32.OpenProcess(
              ACCESS_RIGHTS, False, self.pid
          )
          
          if not self.h_process:
            err = self.kernel32.GetLastError()
            print(f"[MemoryReader] Found {self.process_name} (PID {self.pid}), but OpenProcess failed with Error Code: {err}")
          else:
            print(f"[MemoryReader] Successfully attached to {self.process_name} (PID {self.pid})!")

          self.kernel32.CloseHandle(hSnap)
          return self.h_process is not None

        if not self.kernel32.Process32Next(hSnap, ctypes.byref(pe32)):
          break

    self.kernel32.CloseHandle(hSnap)
    return False

  def get_module_base(self, target_mod_name="blackops3.exe"):
    if not self.pid:
      return 0
    hSnap = self.kernel32.CreateToolhelp32Snapshot(
        TH32CS_SNAPMODULE, self.pid
    )
    if hSnap == -1:
      return 0

    me32 = MODULEENTRY32()
    me32.dwSize = ctypes.sizeof(MODULEENTRY32)

    first_base = 0
    target_base = 0

    if self.kernel32.Module32First(hSnap, ctypes.byref(me32)):
      while True:
        try:
          mod_name = (
              me32.szModule.decode("utf-8", errors="ignore")
              .split("\x00")[0]
              .strip()
              .lower()
          )
        except Exception:
          mod_name = ""

        base = ctypes.cast(me32.modBaseAddr, ctypes.c_void_p).value
        if first_base == 0 and base:
          first_base = base
        if (
            target_mod_name.lower() in mod_name
            or mod_name in target_mod_name.lower()
        ):
          target_base = base
          break
        if not self.kernel32.Module32Next(hSnap, ctypes.byref(me32)):
          break

    self.kernel32.CloseHandle(hSnap)
    return target_base if target_base != 0 else first_base

  def read_int32(self, address):
    if not self.h_process:
      return None
    buffer = ctypes.c_int32()
    bytes_read = ctypes.c_size_t()
    
    success = self.kernel32.ReadProcessMemory(
        self.h_process,
        ctypes.c_void_p(address),
        ctypes.byref(buffer),
        4,
        ctypes.byref(bytes_read),
    )
    
    if not success:
      return None
        
    return buffer.value

  def read_uint32(self, address):
    val = self.read_int32(address)
    if val is None:
      return None
    return val & 0xFFFFFFFF

  def read_bytes(self, address, size):
    if not self.h_process:
      return None
    buffer = ctypes.create_string_buffer(size)
    bytes_read = ctypes.c_size_t()
    success = self.kernel32.ReadProcessMemory(
        self.h_process,
        ctypes.c_void_p(address),
        buffer,
        size,
        ctypes.byref(bytes_read),
    )
    if not success or bytes_read.value != size:
      return None
    return buffer.raw

  def read_byte(self, address):
    raw = self.read_bytes(address, 1)
    if raw is None:
      return None
    return raw[0]

  def read_float(self, address):
    raw = self.read_bytes(address, 4)
    if raw is None:
      return None
    return struct.unpack("f", raw)[0]

  def close(self):
    if self.h_process:
      try:
        self.kernel32.CloseHandle(self.h_process)
      except Exception:
        pass
      self.h_process = None

  def __del__(self):
    self.close()

class ZombiesTrackerApp:

  def __init__(self, root):
    self.root = root
    self.root.title("Zombacus: Zombie Tracker & Calculator")
    self.root.geometry("800x800")
    self.root.configure(bg="#1e1e1e")

    self.accent_rgb = [0, 122, 204]

    self.config_data = {}
    self.selected_gums = [None, None, None, None, None]
    if os.path.exists("zombacus_config.json"):
      try:
        with open("zombacus_config.json", "r") as f:
          self.config_data = json.load(f)
          saved_gums = self.config_data.get("selected_gums")
          if saved_gums and isinstance(saved_gums, list):
            while len(saved_gums) < 5:
              saved_gums.append(None)
            self.selected_gums = saved_gums[:5]
      except Exception as e:
        print(f"Could not pre-load config: {e}")

    try:
      icon_path = resource_path("app_icon.ico")
      if os.path.exists(icon_path):
        pil_ico = Image.open(icon_path)
        self.app_ico = ImageTk.PhotoImage(pil_ico)
        self.root.iconphoto(True, self.app_ico)
    except Exception as e:
      print(f"Could not load window icon: {e}")

    self.icon_filenames = {
        "Max Ammo": "max_ammo.png",
        "Insta-Kill": "insta_kill.png",
        "Double Points": "double_points.png",
        "Nuke": "nuke.png",
        "Carpenter": "carpenter.png",
        "Fire Sale": "fire_sale.png",
        "Death Machine": "death_machine.png",
        "Zombie Blood": "zombie_blood.png",
    }
    self.loaded_images = {}
    self.load_powerup_icons()

    self.gum_data = {
        "Anywhere But Here!": "t7_hud_zm_bgb_anywhere_but_here.png",
        "Alchemical Antithesis": "t7_hud_zm_bgb_alchemical_antithesis.png",
        "In Plain Sight": "t7_hud_zm_bgb_in_plain_sight.png",
        "Now You See Me": "t7_hud_zm_bgb_now_you_see_me.png",
        "Always Done Swiftly": "t7_hud_zm_bgb_always_done_swiftly.png",
        "Armamental Accomplishment": "t7_hud_zm_bgb_armamental_accomplishment.png",
        "Danger Closest": "t7_hud_zm_bgb_danger_closest.png",
        "Firing on All Cylinders": "t7_hud_zm_bgb_firing_on_all_cylinders.png",
        "Lucky Crit": "t7_hud_zm_bgb_lucky_crit.png",
        "Arsenal Accelerator": "t7_hud_zm_bgb_arsenal_accelerator.png",
        "Coagulant": "t7_hud_zm_bgb_coagulant.png",
        "Stock Option": "t7_hud_zm_bgb_stock_option.png",
        "Sword Flay": "t7_hud_zm_bgb_sword_flay.png",
        "Arms Grace": "t7_hud_zm_bgb_arms_grace.png",
        "Impatient": "t7_hud_zm_bgb_impatient.png",
        "Bullet Boost": "t7_hud_zm_bgb_bullet_boost.png",
        "Cache Back": "t7_hud_zm_bgb_cache_back.png",
        "Crawl Space": "t7_hud_zm_bgb_crawl_space.png",
        "Dead of Nuclear Winter": "t7_hud_zm_bgb_dead_of_nuclear_winter.png",
        "Ephemeral Enhancement": "t7_hud_zm_bgb_ephemeral_enhancement.png",
        "Extra Credit": "t7_hud_zm_bgb_extra_credit.png",
        "Fatal Contraption": "t7_hud_zm_bgb_fatal_contraption.png",
        "Fear in Headlights": "t7_hud_zm_bgb_fear_in_headlights.png",
        "Idle Eyes": "t7_hud_zm_bgb_idle_eyes.png",
        "I'm Feelin Lucky": "t7_hud_zm_bgb_im_feelin_lucky.png",
        "Immolation Liquidation": "t7_hud_zm_bgb_immolation_liquidation.png",
        "Kill Joy": "t7_hud_zm_bgb_kill_joy.png",
        "Killing Time": "t7_hud_zm_bgb_killing_time.png",
        "Licensed Contractor": "t7_hud_zm_bgb_licensed_contractor.png",
        "Mind Blown": "t7_hud_zm_bgb_mind_blown.png",
        "On the House": "t7_hud_zm_bgb_on_the_house.png",
        "Phoenix Up": "t7_hud_zm_bgb_phoenix_up.png",
        "Reign Drops": "t7_hud_zm_bgb_reign_drops.png",
        "Respin Cycle": "t7_hud_zm_bgb_respin_cycle.png",
        "Round Robbin": "t7_hud_zm_bgb_round_robbin.png",
        "Who's Keeping Score?": "t7_hud_zm_bgb_whos_keeping_score.png",
        "Aftertaste": "t7_hud_zm_bgb_aftertaste.png",
        "Board Games": "t7_hud_zm_bgb_board_games.png",
        "Head Drama": "t7_hud_zm_bgb_head_drama.png",
        "Near Death Experience": "t7_hud_zm_bgb_near_death_experience.png",
        "Power Vacuum": "t7_hud_zm_bgb_power_vacuum.png",
        "Temporal Gift": "t7_hud_zm_bgb_temporal_gift.png",
        "Board to Death": "t7_hud_zm_bgb_board_to_death.png",
        "Disorderly Combat": "t7_hud_zm_bgb_disorderly_combat.png",
        "Profit Sharing": "t7_hud_zm_bgb_profit_sharing.png",
        "Secret Shopper": "t7_hud_zm_bgb_secret_shopper.png",
        "Shopping Free": "t7_hud_zm_bgb_shopping_free.png",
        "Undead Man Walking": "t7_hud_zm_bgb_undead_man_walking.png",
        "Burned Out": "t7_hud_zm_bgb_burned_out.png",
        "Crate Power": "t7_hud_zm_bgb_crate_power.png",
        "Flavor Hexed": "t7_hud_zm_bgb_flavor_hexed.png",
        "Perkaholic": "t7_hud_zm_bgb_perkaholic.png",
        "Pop Shocks": "t7_hud_zm_bgb_pop_shocks.png",
        "Self Medication": "t7_hud_zm_bgb_self_medication.png",
        "Slaughter Slide": "t7_hud_zm_bgb_slaughter_slide.png",
        "Soda Fountain": "t7_hud_zm_bgb_soda_fountain.png",
        "Unbearable": "t7_hud_zm_bgb_unbearable.png",
        "Unquenchable": "t7_hud_zm_bgb_unquenchable.png",
        "Wall Power": "t7_hud_zm_bgb_wall_power.png",
        "Eye Candy": "t7_hud_zm_bgb_eye_candy.png",
        "Newtonian Negation": "t7_hud_zm_bgb_newtonian_negation.png",
        "Projectile Vomiting": "t7_hud_zm_bgb_projectile_vomiting.png",
        "Tone Death": "t7_hud_zm_bgb_tone_death.png",
    }

    self.classic_gums = {
        "Anywhere But Here!": "t7_hud_zm_bgb_anywhere_but_here.png",
        "Alchemical Antithesis": "t7_hud_zm_bgb_alchemical_antithesis.png",
        "In Plain Sight": "t7_hud_zm_bgb_in_plain_sight.png",
        "Now You See Me": "t7_hud_zm_bgb_now_you_see_me.png",
        "Always Done Swiftly": "t7_hud_zm_bgb_always_done_swiftly.png",
        "Armamental Accomplishment": "t7_hud_zm_bgb_armamental_accomplishment.png",
        "Danger Closest": "t7_hud_zm_bgb_danger_closest.png",
        "Firing on All Cylinders": "t7_hud_zm_bgb_firing_on_all_cylinders.png",
        "Lucky Crit": "t7_hud_zm_bgb_lucky_crit.png",
        "Arsenal Accelerator": "t7_hud_zm_bgb_arsenal_accelerator.png",
        "Coagulant": "t7_hud_zm_bgb_coagulant.png",
        "Stock Option": "t7_hud_zm_bgb_stock_option.png",
        "Sword Flay": "t7_hud_zm_bgb_sword_flay.png",
        "Arms Grace": "t7_hud_zm_bgb_arms_grace.png",
        "Impatient": "t7_hud_zm_bgb_impatient.png",
    }

    self.mega_gums = {
        "Bullet Boost": "t7_hud_zm_bgb_bullet_boost.png",
        "Cache Back": "t7_hud_zm_bgb_cache_back.png",
        "Crawl Space": "t7_hud_zm_bgb_crawl_space.png",
        "Dead of Nuclear Winter": "t7_hud_zm_bgb_dead_of_nuclear_winter.png",
        "Ephemeral Enhancement": "t7_hud_zm_bgb_ephemeral_enhancement.png",
        "Extra Credit": "t7_hud_zm_bgb_extra_credit.png",
        "Fatal Contraption": "t7_hud_zm_bgb_fatal_contraption.png",
        "Fear in Headlights": "t7_hud_zm_bgb_fear_in_headlights.png",
        "Idle Eyes": "t7_hud_zm_bgb_idle_eyes.png",
        "I'm Feelin Lucky": "t7_hud_zm_bgb_im_feelin_lucky.png",
        "Immolation Liquidation": "t7_hud_zm_bgb_immolation_liquidation.png",
        "Kill Joy": "t7_hud_zm_bgb_kill_joy.png",
        "Killing Time": "t7_hud_zm_bgb_killing_time.png",
        "Licensed Contractor": "t7_hud_zm_bgb_licensed_contractor.png",
        "Mind Blown": "t7_hud_zm_bgb_mind_blown.png",
        "On the House": "t7_hud_zm_bgb_on_the_house.png",
        "Phoenix Up": "t7_hud_zm_bgb_phoenix_up.png",
        "Reign Drops": "t7_hud_zm_bgb_reign_drops.png",
        "Respin Cycle": "t7_hud_zm_bgb_respin_cycle.png",
        "Round Robbin": "t7_hud_zm_bgb_round_robbin.png",
        "Who's Keeping Score?": "t7_hud_zm_bgb_whos_keeping_score.png",
        "Aftertaste": "t7_hud_zm_bgb_aftertaste.png",
        "Board Games": "t7_hud_zm_bgb_board_games.png",
        "Head Drama": "t7_hud_zm_bgb_head_drama.png",
        "Near Death Experience": "t7_hud_zm_bgb_near_death_experience.png",
        "Power Vacuum": "t7_hud_zm_bgb_power_vacuum.png",
        "Temporal Gift": "t7_hud_zm_bgb_temporal_gift.png",
        "Board to Death": "t7_hud_zm_bgb_board_to_death.png",
        "Disorderly Combat": "t7_hud_zm_bgb_disorderly_combat.png",
        "Profit Sharing": "t7_hud_zm_bgb_profit_sharing.png",
        "Secret Shopper": "t7_hud_zm_bgb_secret_shopper.png",
        "Shopping Free": "t7_hud_zm_bgb_shopping_free.png",
        "Undead Man Walking": "t7_hud_zm_bgb_undead_man_walking.png",
        "Burned Out": "t7_hud_zm_bgb_burned_out.png",
        "Crate Power": "t7_hud_zm_bgb_crate_power.png",
        "Flavor Hexed": "t7_hud_zm_bgb_flavor_hexed.png",
        "Perkaholic": "t7_hud_zm_bgb_perkaholic.png",
        "Pop Shocks": "t7_hud_zm_bgb_pop_shocks.png",
        "Self Medication": "t7_hud_zm_bgb_self_medication.png",
        "Slaughter Slide": "t7_hud_zm_bgb_slaughter_slide.png",
        "Soda Fountain": "t7_hud_zm_bgb_soda_fountain.png",
        "Unbearable": "t7_hud_zm_bgb_unbearable.png",
        "Unquenchable": "t7_hud_zm_bgb_unquenchable.png",
        "Wall Power": "t7_hud_zm_bgb_wall_power.png",
    }

    self.whimsical_gums = {
        "Eye Candy": "t7_hud_zm_bgb_eye_candy.png",
        "Newtonian Negation": "t7_hud_zm_bgb_newtonian_negation.png",
        "Projectile Vomiting": "t7_hud_zm_bgb_projectile_vomiting.png",
        "Tone Death": "t7_hud_zm_bgb_tone_death.png",
    }

    self.gum_loaded_images = {}
    self.load_gum_icons()

    self.selected_gums = [None, None, None, None, None]
    self.gum_tracker_states = {}
    self.setup_visible = True
    self.sph_visible = False
    self.round_time_visible = False
    self.combined_time_visible = False
    self.auto_compressed = False

    self.timer_running = False
    self.timer_paused = False
    self.timer_start_ticks = 0.0
    self.elapsed_paused_time = 0.0
    self.current_split_index = 0
    self.splits_list = []
    self.asl_script_loaded = False
    self.asl_status_text = "Memory Auto-Split: Idle (Click Load ASL/Script)"
    self.loaded_lss_filename = "Default Generator"

    self.accent_buttons = []
    self.accent_text_labels = []

    self.credit_lbl = tk.Label(
        root,
        text=f"v{APP_VERSION} Developed by GashyDev, Executable by XcDylan93",
        font=("Segoe UI", 8),
        fg="#666666",
        bg="#1e1e1e",
    )
    self.credit_lbl.pack(side="bottom", fill="x", pady=(0, 4))

    self.tab_bar = tk.Frame(root, bg="#1e1e1e")
    self.tab_bar.pack(fill="x", padx=10, pady=(10, 0))

    self.content_container = tk.Frame(root, bg="#1e1e1e")
    self.content_container.pack(fill="both", expand=True, padx=10, pady=10)

    self.calc_tab_container = tk.Frame(self.content_container, bg="#1e1e1e")
    self.gum_combined_frame = tk.Frame(self.content_container, bg="#1e1e1e")
    self.power_frame = tk.Frame(self.content_container, bg="#1e1e1e")
    self.bonus_frame = tk.Frame(self.content_container, bg="#1e1e1e")
    self.boss_frame = tk.Frame(self.content_container, bg="#1e1e1e")
    self.speedrun_frame = tk.Frame(self.content_container, bg="#1e1e1e")
    self.error_tracker_frame = tk.Frame(self.content_container, bg="#1e1e1e")

    self.pages = [
        self.calc_tab_container,
        self.gum_combined_frame,
        self.power_frame,
        self.bonus_frame,
        self.boss_frame,
        self.speedrun_frame,
        self.error_tracker_frame,
    ]

    self.setup_calculator_tab()
    self.setup_gum_combined_tab()
    self.setup_powerup_tab()
    self.setup_bonus_tab()
    self.setup_boss_tab()
    self.setup_speedrun_tab()
    self.setup_error_tracker_tab()

    self.tab_buttons = []

    btn_z = tk.Button(
        self.tab_bar,
        text="   Z   ",
        font=("Death Spirit", 12, "bold"),
        fg="#ff3333",
        activeforeground="#ff3333",
        bg="#2d2d2d",
        activebackground="#007acc",
        relief="flat",
        bd=0,
        padx=12,
        pady=6,
        command=lambda: self.show_page(0),
    )
    btn_z.pack(side="left", padx=(0, 2))
    self.tab_buttons.append(btn_z)

    other_tabs = [
        "Gum Tracker",
        "Powerup Tracker",
        "Bonus Rounds",
        "Boss Rounds",
        "LiveSplit Timer",
        "Error Monitor",
    ]
    for idx, name in enumerate(other_tabs, start=1):
      btn = tk.Button(
          self.tab_bar,
          text=f"  {name}  ",
          font=("Segoe UI", 9, "bold"),
          fg="#ffffff",
          activeforeground="#ffffff",
          bg="#2d2d2d",
          activebackground="#007acc",
          relief="flat",
          bd=0,
          padx=8,
          pady=6,
          command=lambda i=idx: self.show_page(i),
      )
      btn.pack(side="left", padx=2)
      self.tab_buttons.append(btn)

    self.show_page(0)

    self.calculate_zombies()
    self.calculate_bonus_round()
    self.calculate_boss_round()

    self.root.after(1000, self.check_for_updates)
    self.start_timer_loop()
    self.load_config()

  def save_config(self):
    config = {
        "lss_path": getattr(self, "loaded_lss_path", ""),
        "asl_path": getattr(self, "loaded_asl_path", ""),
        "timer_font": getattr(self, "timer_font_var", tk.StringVar(value="Consolas")).get(),
        "selected_gums": getattr(self, "selected_gums", [None, None, None, None, None]),
        "gm_gums": getattr(self, "gm_show_gums", tk.BooleanVar(value=False)).get(),
        "gm_powerups": getattr(self, "gm_show_powerups", tk.BooleanVar(value=False)).get(),
        "gm_bonus": getattr(self, "gm_show_bonus", tk.BooleanVar(value=False)).get(),
        "gm_boss": getattr(self, "gm_show_boss", tk.BooleanVar(value=False)).get(),
        "gm_errors": getattr(self, "gm_show_errors", tk.BooleanVar(value=False)).get(),
        "bonus_preset": self.bonus_preset_combo.get() if hasattr(self, "bonus_preset_combo") else "None",
        "bonus_round": self.bonus_entry.get() if hasattr(self, "bonus_entry") else "5",
        "excavator_loc": getattr(self, "selected_excavator_location", "Tunnel 6"),
        "boss_preset": self.boss_preset_combo.get() if hasattr(self, "boss_preset_combo") else "None",
        "boss_round": self.boss_entry.get() if hasattr(self, "boss_entry") else "8",
        "sr_show_sph": getattr(self, "sr_show_sph", tk.BooleanVar(value=False)).get(),
        "accent_hue": self.hue_slider.get() if hasattr(self, "hue_slider") else 204,
        "accent_sat": self.sat_slider.get() if hasattr(self, "sat_slider") else 100,
        "accent_light": self.light_slider.get() if hasattr(self, "light_slider") else 100,
        "enabled_errors": {item["key"]: item["enabled"] for item in getattr(self, "error_addresses_def", [])},
    }
    try:
      with open("zombacus_config.json", "w") as f:
        json.dump(config, f)
    except Exception as e:
      print(f"Could not save config: {e}")

  def load_config(self):
    if os.path.exists("zombacus_config.json"):
      try:
        with open("zombacus_config.json", "r") as f:
          config = json.load(f)
          
          lss_path = config.get("lss_path")
          if lss_path and os.path.exists(lss_path):
            self.load_lss_splits_file(lss_path)

          asl_path = config.get("asl_path")
          if asl_path and os.path.exists(asl_path):
            self.load_asl_script(asl_path)

          timer_font = config.get("timer_font")
          if timer_font and hasattr(self, "timer_font_var"):
            self.timer_font_var.set(timer_font)
            self.update_timer_font()

          sr_sph = config.get("sr_show_sph")
          if sr_sph is not None and hasattr(self, "sr_show_sph"):
            self.sr_show_sph.set(sr_sph)

          hue = config.get("accent_hue")
          sat = config.get("accent_sat")
          light = config.get("accent_light")
          
          if hue is not None and hasattr(self, "hue_slider"):
            self.hue_slider.set(hue)
          if sat is not None and hasattr(self, "sat_slider"):
            self.sat_slider.set(sat)
          if light is not None and hasattr(self, "light_slider"):
            self.light_slider.set(light)
            
          if hue is not None:
            self.update_accent_from_hue()

          if hasattr(self, "gm_show_gums"):
            self.gm_show_gums.set(config.get("gm_gums", False))
          if hasattr(self, "gm_show_powerups"):
            self.gm_show_powerups.set(config.get("gm_powerups", False))
          if hasattr(self, "gm_show_bonus"):
            self.gm_show_bonus.set(config.get("gm_bonus", False))
          if hasattr(self, "gm_show_boss"):
            self.gm_show_boss.set(config.get("gm_boss", False))
          if hasattr(self, "gm_show_errors"):
            self.gm_show_errors.set(config.get("gm_errors", False))

          bp = config.get("bonus_preset")
          if bp and hasattr(self, "bonus_preset_combo"):
            self.bonus_preset_combo.set(bp)
            self.on_bonus_preset_selected(None)
          br = config.get("bonus_round")
          if br and hasattr(self, "bonus_entry"):
            self.bonus_entry.delete(0, tk.END)
            self.bonus_entry.insert(0, br)
          el = config.get("excavator_loc")
          if el and hasattr(self, "selected_excavator_location"):
            self.selected_excavator_location = el
            self.update_excavator_buttons_ui()

          bsp = config.get("boss_preset")
          if bsp and hasattr(self, "boss_preset_combo"):
            self.boss_preset_combo.set(bsp)
            self.on_boss_preset_selected(None)
          bsr = config.get("boss_round")
          if bsr and hasattr(self, "boss_entry"):
            self.boss_entry.delete(0, tk.END)
            self.boss_entry.insert(0, bsr)

          self.calculate_bonus_round()
          self.calculate_boss_round()

          enabled_errors = config.get("enabled_errors", {})
          if enabled_errors and hasattr(self, "error_addresses_def"):
            for item in self.error_addresses_def:
              if item["key"] in enabled_errors:
                item["enabled"] = bool(enabled_errors[item["key"]])
            if hasattr(self, "et_item_ids") and hasattr(self, "et_tree"):
              for item in self.error_addresses_def:
                key = item["key"]
                if key in self.et_item_ids:
                  tid = self.et_item_ids[key]
                  checkbox_symbol = "☑" if item["enabled"] else "☐"
                  current_vals = self.et_tree.item(tid, "values")
                  if current_vals:
                    self.et_tree.item(
                        tid,
                        values=(
                            checkbox_symbol,
                            current_vals[1],
                            current_vals[2],
                            current_vals[3],
                        ),
                    )

          saved_gums = config.get("selected_gums")
          if saved_gums and isinstance(saved_gums, list):
            while len(saved_gums) < 5:
              saved_gums.append(None)
            self.selected_gums = saved_gums[:5]
            self.update_gum_ui()
            self.rebuild_gum_tracker_grid()

      except Exception as e:
        print(f"Could not load config: {e}")

  def show_page(self, page_index):
    self.current_page_index = page_index
    for frame in self.pages:
      frame.pack_forget()

    self.pages[page_index].pack(fill="both", expand=True)

    if page_index == 0:
      self.calc_canvas.bind_all("<MouseWheel>", self._on_calc_mousewheel)
    else:
      self.calc_canvas.unbind_all("<MouseWheel>")

    for idx, btn in enumerate(self.tab_buttons):
      if idx == page_index:
        btn.config(bg=self.get_accent_hex())
      else:
        btn.config(bg="#2d2d2d")

  def get_accent_hex(self):
    return f"#{self.accent_rgb[0]:02x}{self.accent_rgb[1]:02x}{self.accent_rgb[2]:02x}"

  def update_accent_from_hue(self, val=None):
    hue_val = float(self.hue_slider.get()) / 360.0
    sat_val = float(self.sat_slider.get()) / 100.0 if hasattr(self, "sat_slider") else 1.0
    light_val = float(self.light_slider.get()) / 100.0 if hasattr(self, "light_slider") else 1.0

    self.refresh_saturation_gradient()

    r, g, b = colorsys.hsv_to_rgb(hue_val, sat_val, light_val)
    self.accent_rgb = [int(r * 255), int(g * 255), int(b * 255)]

    hex_c = self.get_accent_hex()

    self.update_powerup_ui()
    if hasattr(self, "gum_card_frames"):
      self.update_gum_tracker_ui()
    if hasattr(self, "slot_buttons"):
      self.update_gum_ui()
    if hasattr(self, "excavator_loc_buttons"):
      self.update_excavator_buttons_ui()
    if hasattr(self, "update_speedrun_ui"):
      self.update_speedrun_ui()
      self.rebuild_sr_splits_ui()

    for btn in self.accent_buttons:
      if btn.winfo_exists():
        btn.config(bg=hex_c)

    for lbl in self.accent_text_labels:
      if lbl.winfo_exists():
        lbl.config(fg=hex_c)

    active_idx = getattr(self, "current_page_index", 0)
    for idx, btn in enumerate(self.tab_buttons):
      if idx == active_idx:
        btn.config(bg=hex_c)
      else:
        btn.config(bg="#2d2d2d")

    self.save_config()

  def refresh_saturation_gradient(self):
    if not hasattr(self, "hue_slider") or not hasattr(self, "sat_img_lbl"):
      return
    hue_val = float(self.hue_slider.get()) / 360.0
    width, height = 75, 8
    im_sat = Image.new("RGB", (width, height))
    pixels_sat = im_sat.load()
    for x in range(width):
      s = x / float(width)
      r, g, b = colorsys.hsv_to_rgb(hue_val, s, 1.0)
      c_val = (int(r * 255), int(g * 255), int(b * 255))
      for y in range(height):
        pixels_sat[x, y] = c_val

    self.sat_img = ImageTk.PhotoImage(im_sat)
    self.sat_img_lbl.config(image=self.sat_img)

  def check_for_updates(self):
    CURRENT_VERSION = APP_VERSION
    VERSION_JSON_URL = "https://raw.githubusercontent.com/XcDylan93/CoD-Zombies-Calculator-Tracker/main/version.json"

    try:
      req = urllib.request.Request(
          VERSION_JSON_URL, headers={"User-Agent": "Mozilla/5.0"}
      )
      with urllib.request.urlopen(req, timeout=3) as response:
        data = json.loads(response.read().decode())

      remote_version = data.get("version")
      download_url = data.get("download_url")

      if remote_version and remote_version != CURRENT_VERSION:
        if messagebox.askyesno(
            "Update Available",
            f"A new version ({remote_version}) is available!\nWould you like to"
            " update now?",
        ):
          self.download_and_apply_update(download_url)
    except Exception as e:
      print(f"Could not check for updates: {e}")

  def download_and_apply_update(self, download_url):
    try:
      if getattr(sys, "frozen", False):
        current_exe_path = sys.executable
        exe_filename = os.path.basename(current_exe_path)
      else:
        messagebox.showinfo(
            "Development Mode",
            "Auto-update only works from the compiled .exe file.",
        )
        return

      app_dir = os.path.dirname(current_exe_path)
      zip_path = os.path.join(app_dir, "update.zip")
      bat_path = os.path.join(app_dir, "update.bat")

      messagebox.showinfo(
          "Downloading",
          "Downloading update package... The application will restart automatically.",
      )
      urllib.request.urlretrieve(download_url, zip_path)

      bat_content = f"""@echo off
      chcp 65001 >nul
      echo Waiting for Zombacus to close...
      taskkill /IM "{exe_filename}" /F > NUL 2>&1
      timeout /t 3 /nobreak > NUL
      
      echo Extracting update...
      powershell -Command "$temp = Join-Path '{app_dir}' 'temp_update'; Expand-Archive -Path '{zip_path}' -DestinationPath $temp -Force; if (Test-Path (Join-Path $temp 'zombacus')) {{ Move-Item -Path '$temp\\zombacus\\*' -Destination '{app_dir}' -Force; Remove-Item '$temp\\zombacus' -Recurse }} else {{ Move-Item -Path '$temp\\*' -Destination '{app_dir}' -Force }}; Remove-Item $temp -Recurse -Force"
      
      echo Cleaning up...
      del "{zip_path}"
      
      echo Restarting application...
      start "" "{current_exe_path}"
      del "%~f0"
      """

      with open(bat_path, "w", encoding="utf-8") as bat_file:
        bat_file.write(bat_content)

      subprocess.Popen(
          ["cmd.exe", "/c", bat_path], creationflags=subprocess.CREATE_NO_WINDOW
      )
      sys.exit(0)
    except Exception as e:
      messagebox.showerror("Update Failed", f"An error occurred: {e}")

  def load_clean_transparent_icon(self, path, max_size):
    img = Image.open(path).convert("RGBA")

    bbox = img.getbbox()
    if bbox:
      img = img.crop(bbox)

    orig_w, orig_h = img.size
    max_w, max_h = max_size

    if orig_w > orig_h:
      icon_w = max_w
      icon_h = int(orig_h * (max_w / orig_w))
    else:
      icon_h = max_h
      icon_w = int(orig_w * (max_h / orig_h))

    img = img.resize((icon_w, icon_h), Image.Resampling.LANCZOS)

    container = Image.new("RGBA", max_size, (0, 0, 0, 0))
    paste_x = (max_w - icon_w) // 2
    paste_y = (max_h - icon_h) // 2
    container.paste(img, (paste_x, paste_y), img)

    datas = container.getdata()
    new_data = []
    for item in datas:
      if item[3] < 128:
        new_data.append((0, 0, 0, 0))
      else:
        new_data.append(item)
    container.putdata(new_data)

    return ImageTk.PhotoImage(container)

  def load_powerup_icons(self):
    self.loaded_images = {}
    self.loaded_pil_images = {}
    for name, filename in self.icon_filenames.items():
      path = resource_path(filename)
      if os.path.exists(path):
        try:
          self.loaded_images[name] = self.load_clean_transparent_icon(path, (64, 64))
          img = Image.open(path).convert("RGBA")
          bbox = img.getbbox()
          if bbox:
            img = img.crop(bbox)
          self.loaded_pil_images[name] = img
        except Exception as e:
          print(f"Could not load image {filename}: {e}")

  def load_gum_icons(self):
    self.gum_loaded_images = {}
    self.gum_loaded_pil_images = {}
    for name, filename in self.gum_data.items():
      path = resource_path(filename)
      if os.path.exists(path):
        try:
          self.gum_loaded_images[name] = self.load_clean_transparent_icon(path, (48, 48))
          img = Image.open(path).convert("RGBA")
          bbox = img.getbbox()
          if bbox:
            img = img.crop(bbox)
          self.gum_loaded_pil_images[name] = img
        except Exception as e:
          print(f"Could not load gum image {filename}: {e}")

  def create_hud_badge(self, pil_img, is_active, size=(42, 42)):
    badge_w, badge_h = size
    badge = Image.new("RGBA", (badge_w, badge_h), (0, 0, 0, 0))

    from PIL import ImageDraw
    draw = ImageDraw.Draw(badge)

    if is_active:
      r, g, b = self.accent_rgb
      border_color = (r, g, b, 255)
      base_color = (r, g, b)
    else:
      border_color = (180, 180, 180, 200)
      base_color = (45, 45, 45)

    radius = 6
    
    draw.rounded_rectangle(
        [0, 0, badge_w - 1, badge_h - 1],
        radius=radius,
        fill=None,
        outline=border_color,
        width=2 if is_active else 1,
    )

    cx, cy = badge_w / 2.0, badge_h / 2.0
    max_dist = max(cx, cy)
    pixels = badge.load()

    for y in range(badge_h):
      for x in range(badge_w):
        if 1 <= x < badge_w - 1 and 1 <= y < badge_h - 1:
          dist = math.sqrt((x - cx)**2 + (y - cy)**2)
          factor = min(1.0, dist / max_dist)
          
          alpha = int(150 * factor + 15)
          
          current_r, current_g, current_b, current_a = pixels[x, y]
          if current_a == 0:
            pixels[x, y] = (base_color[0], base_color[1], base_color[2], alpha)

    if pil_img:
      max_icon_size = badge_h - 12
      orig_w, orig_h = pil_img.size
      
      if orig_w > orig_h:
        icon_w = max_icon_size
        icon_h = int(orig_h * (max_icon_size / orig_w))
      else:
        icon_h = max_icon_size
        icon_w = int(orig_w * (max_icon_size / orig_h))

      icon_resized = pil_img.resize(
          (icon_w, icon_h), Image.Resampling.LANCZOS
      )
      paste_x = (badge_w - icon_w) // 2
      paste_y = (badge_h - icon_h) // 2
      badge.paste(icon_resized, (paste_x, paste_y), icon_resized)

    final_img = Image.new("RGB", (badge_w, badge_h), (0, 0, 2))
    final_img.paste(badge, (0, 0), badge)

    return ImageTk.PhotoImage(final_img)

  def create_hue_picker(self, parent_frame):
    picker_frame = tk.LabelFrame(
        parent_frame,
        text=" Accent Color ",
        font=("Segoe UI", 9, "bold"),
        fg="#ff5555",
        bg="#252526",
        bd=1,
        relief="solid",
    )
    picker_frame.pack(padx=20, pady=8, fill="x")

    content_sub = tk.Frame(picker_frame, bg="#252526")
    content_sub.pack(padx=10, pady=6, fill="x")
    content_sub.columnconfigure(0, weight=1, uniform="equal")
    content_sub.columnconfigure(1, weight=1, uniform="equal")
    content_sub.columnconfigure(2, weight=1, uniform="equal")

    width, height = 75, 8

    hue_col = tk.Frame(content_sub, bg="#252526")
    hue_col.grid(row=0, column=0, padx=3, sticky="ew")

    im_hue = Image.new("RGB", (width, height))
    pixels_hue = im_hue.load()
    for x in range(width):
      h = x / float(width)
      r, g, b = colorsys.hsv_to_rgb(h, 1.0, 1.0)
      c_val = (int(r * 255), int(g * 255), int(b * 255))
      for y in range(height):
        pixels_hue[x, y] = c_val

    self.rainbow_img = ImageTk.PhotoImage(im_hue)
    tk.Label(hue_col, image=self.rainbow_img, bg="#252526", bd=0).pack(pady=(0, 2))

    self.hue_slider = tk.Scale(
        hue_col,
        from_=0,
        to=360,
        orient="horizontal",
        command=self.update_accent_from_hue,
        bg="#252526",
        fg="#d4d4d4",
        highlightthickness=0,
        troughcolor="#333333",
        label="Hue",
        font=("Segoe UI", 8),
    )
    self.hue_slider.set(204)
    self.hue_slider.pack(fill="x")

    sat_col = tk.Frame(content_sub, bg="#252526")
    sat_col.grid(row=0, column=1, padx=3, sticky="ew")

    im_sat = Image.new("RGB", (width, height))
    pixels_sat = im_sat.load()
    for x in range(width):
      s = x / float(width)
      r, g, b = colorsys.hsv_to_rgb(0.55, s, 1.0)
      c_val = (int(r * 255), int(g * 255), int(b * 255))
      for y in range(height):
        pixels_sat[x, y] = c_val

    self.sat_img = ImageTk.PhotoImage(im_sat)
    self.sat_img_lbl = tk.Label(sat_col, image=self.sat_img, bg="#252526", bd=0)
    self.sat_img_lbl.pack(pady=(0, 2))

    self.sat_slider = tk.Scale(
        sat_col,
        from_=0,
        to=100,
        orient="horizontal",
        command=self.update_accent_from_hue,
        bg="#252526",
        fg="#d4d4d4",
        highlightthickness=0,
        troughcolor="#333333",
        label="Sat",
        font=("Segoe UI", 8),
    )
    self.sat_slider.set(100)
    self.sat_slider.pack(fill="x")

    light_col = tk.Frame(content_sub, bg="#252526")
    light_col.grid(row=0, column=2, padx=3, sticky="ew")

    im_light = Image.new("RGB", (width, height))
    pixels_light = im_light.load()
    for x in range(width):
      v = x / float(width)
      c_val = (int(v * 255), int(v * 255), int(v * 255))
      for y in range(height):
        pixels_light[x, y] = c_val

    self.lightness_img = ImageTk.PhotoImage(im_light)
    tk.Label(light_col, image=self.lightness_img, bg="#252526", bd=0).pack(pady=(0, 2))

    self.light_slider = tk.Scale(
        light_col,
        from_=0,
        to=100,
        orient="horizontal",
        command=self.update_accent_from_hue,
        bg="#252526",
        fg="#d4d4d4",
        highlightthickness=0,
        troughcolor="#333333",
        label="Light",
        font=("Segoe UI", 8),
    )
    self.light_slider.set(100)
    self.light_slider.pack(fill="x")

  def _on_calc_mousewheel(self, event):
    if hasattr(self, "calc_canvas"):
      self.calc_canvas.yview_scroll(int(-1 * (event.delta / 120)), "units")

  def setup_calculator_tab(self):
    self.calc_canvas = tk.Canvas(
        self.calc_tab_container, bg="#1e1e1e", highlightthickness=0
    )
    self.calc_scrollbar = ttk.Scrollbar(
        self.calc_tab_container, orient="vertical", command=self.calc_canvas.yview
    )
    self.calc_frame = tk.Frame(self.calc_canvas, bg="#1e1e1e")

    self.calc_frame.bind(
        "<Configure>",
        lambda e: self.calc_canvas.configure(
            scrollregion=self.calc_canvas.bbox("all")
        ),
    )

    self.calc_canvas_window = self.calc_canvas.create_window(
        (0, 0), window=self.calc_frame, anchor="nw"
    )
    self.calc_canvas.bind(
        "<Configure>",
        lambda e: self.calc_canvas.itemconfig(
            self.calc_canvas_window, width=e.width
        ),
    )

    self.calc_canvas.configure(yscrollcommand=self.calc_scrollbar.set)
    self.calc_canvas.pack(side="left", fill="both", expand=True)
    self.calc_scrollbar.pack(side="right", fill="y")

    title_lbl = tk.Label(
        self.calc_frame,
        text="Zombie Round Stats",
        font=("Death Spirit", 16),
        fg="#ff5555",
        bg="#1e1e1e",
    )
    title_lbl.pack(pady=(12, 5))
    self.accent_text_labels.append(title_lbl)

    self.create_hue_picker(self.calc_frame)

    input_frame = tk.Frame(self.calc_frame, bg="#252526", padx=15, pady=15)
    input_frame.pack(padx=20, pady=5, fill="x")

    tk.Label(
        input_frame,
        text="Mode Preset:",
        font=("Segoe UI", 11),
        fg="#d4d4d4",
        bg="#252526",
    ).grid(row=0, column=0, sticky="w", pady=5)
    self.calc_preset_combo = ttk.Combobox(
        input_frame, values=["Standard", "Modern"], width=12, state="readonly"
    )
    self.calc_preset_combo.current(0)
    self.calc_preset_combo.grid(row=0, column=1, padx=10, sticky="w")
    self.calc_preset_combo.bind(
        "<<ComboboxSelected>>", lambda event: self.calculate_zombies()
    )

    tk.Label(
        input_frame,
        text="Current Round:",
        font=("Segoe UI", 11),
        fg="#d4d4d4",
        bg="#252526",
    ).grid(row=1, column=0, sticky="w", pady=5)

    round_ctrl_frame = tk.Frame(input_frame, bg="#252526")
    round_ctrl_frame.grid(row=1, column=1, padx=10, sticky="w")

    self.btn_minus = tk.Button(
        round_ctrl_frame,
        text="-",
        command=self.decrement_round,
        font=("Segoe UI", 10, "bold"),
        bg=self.get_accent_hex(),
        fg="#ffffff",
        width=3,
        relief="flat",
    )
    self.btn_minus.pack(side="left", padx=(0, 5))
    self.accent_buttons.append(self.btn_minus)

    self.round_entry = tk.Entry(
        round_ctrl_frame,
        font=("Segoe UI", 11),
        width=5,
        bg="#333333",
        fg="#ffffff",
        insertbackground="white",
        justify="center",
    )
    self.round_entry.insert(0, "1")
    self.round_entry.pack(side="left", padx=2)
    self.round_entry.bind("<Return>", lambda event: self.calculate_zombies())

    self.btn_plus = tk.Button(
        round_ctrl_frame,
        text="+",
        command=self.increment_round,
        font=("Segoe UI", 10, "bold"),
        bg=self.get_accent_hex(),
        fg="#ffffff",
        width=3,
        relief="flat",
    )
    self.btn_plus.pack(side="left", padx=(5, 0))
    self.accent_buttons.append(self.btn_plus)

    tk.Label(
        input_frame,
        text="Player Count:",
        font=("Segoe UI", 11),
        fg="#d4d4d4",
        bg="#252526",
    ).grid(row=2, column=0, sticky="w", pady=5)
    self.players_spin = ttk.Combobox(
        input_frame, values=["1", "2", "3", "4"], width=8, state="readonly"
    )
    self.players_spin.current(0)
    self.players_spin.grid(row=2, column=1, padx=10, sticky="w")
    self.players_spin.bind(
        "<<ComboboxSelected>>", lambda event: self.calculate_zombies()
    )

    calc_btn = tk.Button(
        input_frame,
        text="Calculate Round Stats",
        command=self.calculate_zombies,
        font=("Segoe UI", 10, "bold"),
        bg=self.get_accent_hex(),
        fg="#ffffff",
        relief="flat",
        padx=12,
        pady=6,
    )
    calc_btn.grid(row=3, column=0, columnspan=2, pady=15)
    self.accent_buttons.append(calc_btn)

    output_outer = tk.Frame(self.calc_frame, bg="#252526", padx=15, pady=12)
    output_outer.pack(padx=20, pady=10, fill="x")

    row_definitions = [
        ("Round:", lambda: self.val_round_lbl),
        ("Zombies This Round:", lambda: self.val_zombies_lbl),
        ("Hordes (24 per horde):", lambda: self.val_hordes_lbl),
        ("Zombie Health:", lambda: self.val_health_lbl),
        ("Zombies up to round 1:", lambda: self.val_cumulative_lbl),
    ]

    for i, (label_text, lbl_getter) in enumerate(row_definitions):
      row_frame = tk.Frame(output_outer, bg="#252526", padx=5, pady=6)
      row_frame.pack(fill="x")
      row_frame.grid_columnconfigure(1, weight=1)

      tag_lbl = tk.Label(
          row_frame,
          text=label_text,
          font=("Segoe UI", 11),
          fg="#d4d4d4",
          bg="#252526",
          anchor="w",
      )
      tag_lbl.grid(row=0, column=0, sticky="w")

      val_lbl = tk.Label(
          row_frame,
          text="-",
          font=("Segoe UI", 11, "bold"),
          fg=self.get_accent_hex(),
          bg="#252526",
          anchor="e",
      )
      val_lbl.grid(row=0, column=1, sticky="e")
      self.accent_text_labels.append(val_lbl)

      if i == 0:
        self.val_round_lbl = val_lbl
      elif i == 1:
        self.val_zombies_lbl = val_lbl
      elif i == 2:
        self.val_hordes_lbl = val_lbl
      elif i == 3:
        self.val_health_lbl = val_lbl
      elif i == 4:
        self.lbl_cumulative_tag = tag_lbl
        self.val_cumulative_lbl = val_lbl

      if i < len(row_definitions) - 1:
        sep = tk.Frame(output_outer, bg="#333333", height=1)
        sep.pack(fill="x", pady=2)

    self.sph_section = tk.Frame(self.calc_frame, bg="#252526", padx=10, pady=10)
    self.sph_section.pack(padx=20, fill="x", pady=5)

    sph_header = tk.Frame(self.sph_section, bg="#252526")
    sph_header.pack(fill="x", padx=5, pady=(0, 6))

    tk.Label(
        sph_header,
        text="SPH Calculator (Seconds Per Horde):",
        font=("Segoe UI", 9, "bold"),
        fg="#ff5555",
        bg="#252526",
    ).pack(side="left")

    self.toggle_sph_btn = tk.Button(
        sph_header,
        text="▶ Show SPH Calculator",
        command=self.toggle_sph_section,
        font=("Segoe UI", 8),
        bg="#333333",
        fg="#ffffff",
        relief="flat",
        padx=6,
        pady=1,
    )
    self.toggle_sph_btn.pack(side="right")

    self.sph_body = tk.Frame(self.sph_section, bg="#252526")

    tk.Label(
        self.sph_body,
        text="Hours:",
        font=("Segoe UI", 9),
        fg="#d4d4d4",
        bg="#252526",
    ).grid(row=0, column=0, sticky="w", pady=3)
    h_ctrl = tk.Frame(self.sph_body, bg="#252526")
    h_ctrl.grid(row=0, column=1, sticky="w", pady=3, padx=5)
    btn_h_minus = tk.Button(
        h_ctrl,
        text="-",
        command=lambda: self.adjust_time(self.sph_h_entry, -1),
        font=("Segoe UI", 8, "bold"),
        bg=self.get_accent_hex(),
        fg="#ffffff",
        width=2,
        relief="flat",
    )
    btn_h_minus.pack(side="left")
    self.accent_buttons.append(btn_h_minus)
    self.sph_h_entry = tk.Entry(
        h_ctrl,
        width=4,
        font=("Segoe UI", 10),
        bg="#333333",
        fg="#ffffff",
        justify="center",
        insertbackground="white",
    )
    self.sph_h_entry.insert(0, "0")
    self.sph_h_entry.pack(side="left", padx=3)
    self.sph_h_entry.bind("<KeyRelease>", lambda e: self.calculate_sph())
    btn_h_plus = tk.Button(
        h_ctrl,
        text="+",
        command=lambda: self.adjust_time(self.sph_h_entry, 1),
        font=("Segoe UI", 8, "bold"),
        bg=self.get_accent_hex(),
        fg="#ffffff",
        width=2,
        relief="flat",
    )
    btn_h_plus.pack(side="left")
    self.accent_buttons.append(btn_h_plus)

    tk.Label(
        self.sph_body,
        text="Minutes:",
        font=("Segoe UI", 9),
        fg="#d4d4d4",
        bg="#252526",
    ).grid(row=1, column=0, sticky="w", pady=3)
    m_ctrl = tk.Frame(self.sph_body, bg="#252526")
    m_ctrl.grid(row=1, column=1, sticky="w", pady=3, padx=5)
    btn_m_minus = tk.Button(
        m_ctrl,
        text="-",
        command=lambda: self.adjust_time(self.sph_m_entry, -1, 0, 59),
        font=("Segoe UI", 8, "bold"),
        bg=self.get_accent_hex(),
        fg="#ffffff",
        width=2,
        relief="flat",
    )
    btn_m_minus.pack(side="left")
    self.accent_buttons.append(btn_m_minus)
    self.sph_m_entry = tk.Entry(
        m_ctrl,
        width=4,
        font=("Segoe UI", 10),
        bg="#333333",
        fg="#ffffff",
        justify="center",
        insertbackground="white",
    )
    self.sph_m_entry.insert(0, "0")
    self.sph_m_entry.pack(side="left", padx=3)
    self.sph_m_entry.bind("<KeyRelease>", lambda e: self.calculate_sph())
    btn_m_plus = tk.Button(
        m_ctrl,
        text="+",
        command=lambda: self.adjust_time(self.sph_m_entry, 1, 0, 59),
        font=("Segoe UI", 8, "bold"),
        bg=self.get_accent_hex(),
        fg="#ffffff",
        width=2,
        relief="flat",
    )
    btn_m_plus.pack(side="left")
    self.accent_buttons.append(btn_m_plus)

    tk.Label(
        self.sph_body,
        text="Seconds:",
        font=("Segoe UI", 9),
        fg="#d4d4d4",
        bg="#252526",
    ).grid(row=2, column=0, sticky="w", pady=3)
    s_ctrl = tk.Frame(self.sph_body, bg="#252526")
    s_ctrl.grid(row=2, column=1, sticky="w", pady=3, padx=5)
    btn_s_minus = tk.Button(
        s_ctrl,
        text="-",
        command=lambda: self.adjust_time(self.sph_s_entry, -1, 0, 59),
        font=("Segoe UI", 8, "bold"),
        bg=self.get_accent_hex(),
        fg="#ffffff",
        width=2,
        relief="flat",
    )
    btn_s_minus.pack(side="left")
    self.accent_buttons.append(btn_s_minus)
    self.sph_s_entry = tk.Entry(
        s_ctrl,
        width=4,
        font=("Segoe UI", 10),
        bg="#333333",
        fg="#ffffff",
        justify="center",
        insertbackground="white",
    )
    self.sph_s_entry.insert(0, "0")
    self.sph_s_entry.pack(side="left", padx=3)
    self.sph_s_entry.bind("<KeyRelease>", lambda e: self.calculate_sph())
    btn_s_plus = tk.Button(
        s_ctrl,
        text="+",
        command=lambda: self.adjust_time(self.sph_s_entry, 1, 0, 59),
        font=("Segoe UI", 8, "bold"),
        bg=self.get_accent_hex(),
        fg="#ffffff",
        width=2,
        relief="flat",
    )
    btn_s_plus.pack(side="left")
    self.accent_buttons.append(btn_s_plus)

    sph_result_frame = tk.Frame(self.sph_body, bg="#252526")
    sph_result_frame.grid(
        row=3, column=0, columnspan=2, sticky="ew", pady=(8, 2)
    )
    sph_result_frame.grid_columnconfigure(1, weight=1)

    tk.Label(
        sph_result_frame,
        text="Result SPH:",
        font=("Segoe UI", 10, "bold"),
        fg="#d4d4d4",
        bg="#252526",
    ).grid(row=0, column=0, sticky="w")

    self.sph_result_lbl = tk.Label(
        sph_result_frame,
        text="-",
        font=("Segoe UI", 11, "bold"),
        fg=self.get_accent_hex(),
        bg="#252526",
        anchor="e",
    )
    self.sph_result_lbl.grid(row=0, column=1, sticky="e")
    self.accent_text_labels.append(self.sph_result_lbl)

    self.round_time_section = tk.Frame(
        self.calc_frame, bg="#252526", padx=10, pady=10
    )
    self.round_time_section.pack(padx=20, fill="x", pady=5)

    rt_header = tk.Frame(self.round_time_section, bg="#252526")
    rt_header.pack(fill="x", padx=5, pady=(0, 6))

    tk.Label(
        rt_header,
        text="Round Time Calculator:",
        font=("Segoe UI", 9, "bold"),
        fg="#ff5555",
        bg="#252526",
    ).pack(side="left")

    self.toggle_round_time_btn = tk.Button(
        rt_header,
        text="▶ Show Round Time Calculator",
        command=self.toggle_round_time_section,
        font=("Segoe UI", 8),
        bg="#333333",
        fg="#ffffff",
        relief="flat",
        padx=6,
        pady=1,
    )
    self.toggle_round_time_btn.pack(side="right")

    self.round_time_body = tk.Frame(self.round_time_section, bg="#252526")

    tk.Label(
        self.round_time_body,
        text="Input SPH:",
        font=("Segoe UI", 9),
        fg="#d4d4d4",
        bg="#252526",
    ).grid(row=0, column=0, sticky="w", pady=3)
    sph_input_ctrl = tk.Frame(self.round_time_body, bg="#252526")
    sph_input_ctrl.grid(row=0, column=1, sticky="w", pady=3, padx=5)
    btn_rts_minus = tk.Button(
        sph_input_ctrl,
        text="-",
        command=lambda: self.adjust_float_time(self.rt_sph_entry, -1.0),
        font=("Segoe UI", 8, "bold"),
        bg=self.get_accent_hex(),
        fg="#ffffff",
        width=2,
        relief="flat",
    )
    btn_rts_minus.pack(side="left")
    self.accent_buttons.append(btn_rts_minus)
    self.rt_sph_entry = tk.Entry(
        sph_input_ctrl,
        width=6,
        font=("Segoe UI", 10),
        bg="#333333",
        fg="#ffffff",
        justify="center",
        insertbackground="white",
    )
    self.rt_sph_entry.insert(0, "60.0")
    self.rt_sph_entry.pack(side="left", padx=3)
    self.rt_sph_entry.bind(
        "<KeyRelease>", lambda e: self.calculate_round_time()
    )
    btn_rts_plus = tk.Button(
        sph_input_ctrl,
        text="+",
        command=lambda: self.adjust_float_time(self.rt_sph_entry, 1.0),
        font=("Segoe UI", 8, "bold"),
        bg=self.get_accent_hex(),
        fg="#ffffff",
        width=2,
        relief="flat",
    )
    btn_rts_plus.pack(side="left")
    self.accent_buttons.append(btn_rts_plus)

    rt_result_frame = tk.Frame(self.round_time_body, bg="#252526")
    rt_result_frame.grid(
        row=1, column=0, columnspan=2, sticky="ew", pady=(8, 2)
    )
    rt_result_frame.grid_columnconfigure(1, weight=1)

    tk.Label(
        rt_result_frame,
        text="Estimated Round Time:",
        font=("Segoe UI", 10, "bold"),
        fg="#d4d4d4",
        bg="#252526",
    ).grid(row=0, column=0, sticky="w")

    self.rt_result_lbl = tk.Label(
        rt_result_frame,
        text="-",
        font=("Segoe UI", 11, "bold"),
        fg=self.get_accent_hex(),
        bg="#252526",
        anchor="e",
    )
    self.rt_result_lbl.grid(row=0, column=1, sticky="e")
    self.accent_text_labels.append(self.rt_result_lbl)

    self.combined_time_section = tk.Frame(
        self.calc_frame, bg="#252526", padx=10, pady=10
    )
    self.combined_time_section.pack(padx=20, fill="x", pady=5)

    ct_header = tk.Frame(self.combined_time_section, bg="#252526")
    ct_header.pack(fill="x", padx=5, pady=(0, 6))

    tk.Label(
        ct_header,
        text="Combined Round Time Estimator:",
        font=("Segoe UI", 9, "bold"),
        fg="#ff5555",
        bg="#252526",
    ).pack(side="left")

    self.toggle_combined_time_btn = tk.Button(
        ct_header,
        text="▶ Show Combined Round Time Estimator",
        command=self.toggle_combined_time_section,
        font=("Segoe UI", 8),
        bg="#333333",
        fg="#ffffff",
        relief="flat",
        padx=6,
        pady=1,
    )
    self.toggle_combined_time_btn.pack(side="right")

    self.combined_time_body = tk.Frame(
        self.combined_time_section, bg="#252526"
    )

    tk.Label(
        self.combined_time_body,
        text="Input SPH:",
        font=("Segoe UI", 9),
        fg="#d4d4d4",
        bg="#252526",
    ).grid(row=0, column=0, sticky="w", pady=3)
    ct_sph_ctrl = tk.Frame(self.combined_time_body, bg="#252526")
    ct_sph_ctrl.grid(row=0, column=1, sticky="w", pady=3, padx=5)
    btn_cts_minus = tk.Button(
        ct_sph_ctrl,
        text="-",
        command=lambda: self.adjust_float_time(self.ct_sph_entry, -1.0),
        font=("Segoe UI", 8, "bold"),
        bg=self.get_accent_hex(),
        fg="#ffffff",
        width=2,
        relief="flat",
    )
    btn_cts_minus.pack(side="left")
    self.accent_buttons.append(btn_cts_minus)
    self.ct_sph_entry = tk.Entry(
        ct_sph_ctrl,
        width=6,
        font=("Segoe UI", 10),
        bg="#333333",
        fg="#ffffff",
        justify="center",
        insertbackground="white",
    )
    self.ct_sph_entry.insert(0, "60.0")
    self.ct_sph_entry.pack(side="left", padx=3)
    self.ct_sph_entry.bind(
        "<KeyRelease>", lambda e: self.calculate_combined_time()
    )
    btn_cts_plus = tk.Button(
        ct_sph_ctrl,
        text="+",
        command=lambda: self.adjust_float_time(self.ct_sph_entry, 1.0),
        font=("Segoe UI", 8, "bold"),
        bg=self.get_accent_hex(),
        fg="#ffffff",
        width=2,
        relief="flat",
    )
    btn_cts_plus.pack(side="left")
    self.accent_buttons.append(btn_cts_plus)

    tk.Label(
        self.combined_time_body,
        text="Start Round:",
        font=("Segoe UI", 9),
        fg="#d4d4d4",
        bg="#252526",
    ).grid(row=1, column=0, sticky="w", pady=3)
    ct_start_ctrl = tk.Frame(self.combined_time_body, bg="#252526")
    ct_start_ctrl.grid(row=1, column=1, sticky="w", pady=3, padx=5)
    btn_start_minus = tk.Button(
        ct_start_ctrl,
        text="-",
        command=lambda: self.adjust_round_field(self.ct_start_entry, -1),
        font=("Segoe UI", 8, "bold"),
        bg=self.get_accent_hex(),
        fg="#ffffff",
        width=2,
        relief="flat",
    )
    btn_start_minus.pack(side="left")
    self.accent_buttons.append(btn_start_minus)
    self.ct_start_entry = tk.Entry(
        ct_start_ctrl,
        width=4,
        font=("Segoe UI", 10),
        bg="#333333",
        fg="#ffffff",
        justify="center",
        insertbackground="white",
    )
    self.ct_start_entry.insert(0, "1")
    self.ct_start_entry.pack(side="left", padx=3)
    self.ct_start_entry.bind(
        "<KeyRelease>", lambda e: self.calculate_combined_time()
    )
    btn_start_plus = tk.Button(
        ct_start_ctrl,
        text="+",
        command=lambda: self.adjust_round_field(self.ct_start_entry, 1),
        font=("Segoe UI", 8, "bold"),
        bg=self.get_accent_hex(),
        fg="#ffffff",
        width=2,
        relief="flat",
    )
    btn_start_plus.pack(side="left")
    self.accent_buttons.append(btn_start_plus)

    tk.Label(
        self.combined_time_body,
        text="End Round:",
        font=("Segoe UI", 9),
        fg="#d4d4d4",
        bg="#252526",
    ).grid(row=2, column=0, sticky="w", pady=3)
    ct_end_ctrl = tk.Frame(self.combined_time_body, bg="#252526")
    ct_end_ctrl.grid(row=2, column=1, sticky="w", pady=3, padx=5)
    btn_end_minus = tk.Button(
        ct_end_ctrl,
        text="-",
        command=lambda: self.adjust_round_field(self.ct_end_entry, -1),
        font=("Segoe UI", 8, "bold"),
        bg=self.get_accent_hex(),
        fg="#ffffff",
        width=2,
        relief="flat",
    )
    btn_end_minus.pack(side="left")
    self.accent_buttons.append(btn_end_minus)
    self.ct_end_entry = tk.Entry(
        ct_end_ctrl,
        width=4,
        font=("Segoe UI", 10),
        bg="#333333",
        fg="#ffffff",
        justify="center",
        insertbackground="white",
    )
    self.ct_end_entry.insert(0, "20")
    self.ct_end_entry.pack(side="left", padx=3)
    self.ct_end_entry.bind(
        "<KeyRelease>", lambda e: self.calculate_combined_time()
    )
    btn_end_plus = tk.Button(
        ct_end_ctrl,
        text="+",
        command=lambda: self.adjust_round_field(self.ct_end_entry, 1),
        font=("Segoe UI", 8, "bold"),
        bg=self.get_accent_hex(),
        fg="#ffffff",
        width=2,
        relief="flat",
    )
    btn_end_plus.pack(side="left")
    self.accent_buttons.append(btn_end_plus)

    calc_ct_btn = tk.Button(
        self.combined_time_body,
        text="Calculate Total Time",
        command=self.calculate_combined_time,
        font=("Segoe UI", 9, "bold"),
        bg=self.get_accent_hex(),
        fg="#ffffff",
        relief="flat",
        padx=10,
        pady=4,
    )
    calc_ct_btn.grid(row=3, column=0, columnspan=2, pady=(8, 4))
    self.accent_buttons.append(calc_ct_btn)

    ct_result_frame = tk.Frame(self.combined_time_body, bg="#252526")
    ct_result_frame.grid(
        row=4, column=0, columnspan=2, sticky="ew", pady=(4, 2)
    )
    ct_result_frame.grid_columnconfigure(1, weight=1)

    tk.Label(
        ct_result_frame,
        text="Combined Time:",
        font=("Segoe UI", 10, "bold"),
        fg="#d4d4d4",
        bg="#252526",
    ).grid(row=0, column=0, sticky="w")

    self.ct_result_lbl = tk.Label(
        ct_result_frame,
        text="-",
        font=("Segoe UI", 11, "bold"),
        fg=self.get_accent_hex(),
        bg="#252526",
        anchor="e",
    )
    self.ct_result_lbl.grid(row=0, column=1, sticky="e")
    self.accent_text_labels.append(self.ct_result_lbl)

  def toggle_sph_section(self):
    if self.sph_visible:
      self.sph_body.pack_forget()
      self.toggle_sph_btn.config(text="▶ Show SPH Calculator")
      self.sph_visible = False
    else:
      self.sph_body.pack(fill="x", pady=(2, 0))
      self.toggle_sph_btn.config(text="▼ Hide SPH Calculator")
      self.sph_visible = True

  def toggle_round_time_section(self):
    if self.round_time_visible:
      self.round_time_body.pack_forget()
      self.toggle_round_time_btn.config(text="▶ Show Round Time Calculator")
      self.round_time_visible = False
    else:
      self.round_time_body.pack(fill="x", pady=(2, 0))
      self.toggle_round_time_btn.config(text="▼ Hide Round Time Calculator")
      self.round_time_visible = True

  def toggle_combined_time_section(self):
    if self.combined_time_visible:
      self.combined_time_body.pack_forget()
      self.toggle_combined_time_btn.config(
          text="▶ Show Combined Round Time Estimator"
      )
      self.combined_time_visible = False
    else:
      self.combined_time_body.pack(fill="x", pady=(2, 0))
      self.toggle_combined_time_btn.config(
          text="▼ Hide Combined Round Time Estimator"
      )
      self.combined_time_visible = True

  def adjust_time(self, entry_widget, delta, min_val=0, max_val=None):
    try:
      val = int(entry_widget.get())
    except ValueError:
      val = 0
    val += delta
    if val < min_val:
      val = min_val
    if max_val is not None and val > max_val:
      val = max_val
    entry_widget.delete(0, tk.END)
    entry_widget.insert(0, str(val))
    self.calculate_sph()

  def adjust_float_time(self, entry_widget, delta):
    try:
      val = float(entry_widget.get())
    except ValueError:
      val = 0.0
    val += delta
    if val < 0.0:
      val = 0.0
    entry_widget.delete(0, tk.END)
    entry_widget.insert(0, f"{val:.1f}")
    if entry_widget == self.rt_sph_entry:
      self.calculate_round_time()
    elif entry_widget == self.ct_sph_entry:
      self.calculate_combined_time()

  def adjust_round_field(self, entry_widget, delta, min_val=1):
    try:
      val = int(entry_widget.get())
    except ValueError:
      val = min_val
    val += delta
    if val < min_val:
      val = min_val
    entry_widget.delete(0, tk.END)
    entry_widget.insert(0, str(val))
    self.calculate_combined_time()

  def increment_round(self):
    try:
      val = int(self.round_entry.get())
    except ValueError:
      val = 0
    self.round_entry.delete(0, tk.END)
    self.round_entry.insert(0, str(val + 1))
    self.calculate_zombies()

  def decrement_round(self):
    try:
      val = int(self.round_entry.get())
    except ValueError:
      val = 2
    if val > 1:
      self.round_entry.delete(0, tk.END)
      self.round_entry.insert(0, str(val - 1))
      self.calculate_zombies()

  def get_zombies_for_round(self, r_num, players_count):
    for item in self.bonus_history:
      item_rnd = item["round"] if isinstance(item, dict) else item
      if item_rnd == r_num:
        preset = (
            item["preset"]
            if isinstance(item, dict)
            else self.bonus_preset_combo.get()
        )

        if preset == "None":
          break

        matching = [
            x
            for x in self.bonus_history
            if (isinstance(x, dict) and x["round"] <= r_num and x["preset"] == preset)
            or (not isinstance(x, dict) and x <= r_num)
        ]
        occurrence_idx = len(matching)

        if preset in [
            "Dogs",
            "Spiders",
            "Shadows of Evil",
            "Der Eisendrache",
            "Gorod Krovi",
        ]:
          return (
              (players_count * 6)
              if occurrence_idx < 3
              else (players_count * 8)
          )
        elif preset == "Monkeys":
          pack_max = (
              (players_count + occurrence_idx)
              if players_count > occurrence_idx
              else (players_count * 2)
          )
          return pack_max * 3
        elif preset == "Revelations":
          n_num = (
              18
              if players_count == 1
              else (
                  21
                  if players_count == 2
                  else (24 if players_count == 3 else 30)
              )
          )
          if occurrence_idx > 1:
            n_num += 10 * (occurrence_idx - 1)
          parasites_base = (
              n_num
              if occurrence_idx == 1
              else (
                  int(n_num * 0.6)
                  if occurrence_idx == 2
                  else int(n_num * 0.5)
              )
          )
          return n_num + int(parasites_base * 0.1)

    preset = self.calc_preset_combo.get()
    if preset == "Modern":
      return self.get_modern_zombies_for_round(r_num, players_count)
    else:
      return self.get_standard_zombies_for_round(r_num, players_count)

  def calculate_zombies(self):
    try:
      round_num = int(self.round_entry.get())
      players = int(self.players_spin.get())
      if round_num < 1:
        raise ValueError
    except ValueError:
      messagebox.showerror(
          "Invalid Input",
          "Please enter a valid round number greater than or equal to 1.",
      )
      return

    preset = self.calc_preset_combo.get()
    zombies = self.get_zombies_for_round(round_num, players)
    cumulative = sum(
        self.get_zombies_for_round(r, players) for r in range(1, round_num + 1)
    )

    if preset == "Modern":
      health = self.ai_calculate_health(150, round_num)
    else:
      if round_num <= 9:
        health = 150 + (round_num - 1) * 100
      else:
        health = 950
        for r in range(10, round_num + 1):
          health = int(health * 1.1)

      if round_num > 162:
        health = 2147483647

    is_current_bonus = any(
        (item["round"] if isinstance(item, dict) else item) == round_num
        for item in self.bonus_history
    ) and self.bonus_preset_combo.get() != "None"

    hordes = zombies / 24.0

    self.val_round_lbl.config(text=f"{round_num}")
    self.val_zombies_lbl.config(
        text=f"{zombies:,} (Bonus Round)" if is_current_bonus else f"{zombies:,}"
    )
    self.val_hordes_lbl.config(text=f"{hordes:.2f}")
    self.val_health_lbl.config(text=f"{health:,} HP")

    self.lbl_cumulative_tag.config(text=f"Zombies up to round {round_num}:")
    self.val_cumulative_lbl.config(text=f"{cumulative:,}")

    self.calculate_sph()
    self.calculate_round_time()
    self.calculate_combined_time()

  def calculate_sph(self):
    try:
      h = float(self.sph_h_entry.get()) if self.sph_h_entry.get().strip() else 0.0
      m = float(self.sph_m_entry.get()) if self.sph_m_entry.get().strip() else 0.0
      s = float(self.sph_s_entry.get()) if self.sph_s_entry.get().strip() else 0.0
    except ValueError:
      return

    total_seconds = (h * 3600.0) + (m * 60.0) + s

    try:
      round_num = int(self.round_entry.get())
      players = int(self.players_spin.get())
      zombies = self.get_zombies_for_round(round_num, players)
      hordes = zombies / 24.0
    except Exception:
      hordes = 0.0

    if hordes <= 0:
      self.sph_result_lbl.config(text="0.00s / horde")
      return

    sph = total_seconds / hordes
    self.sph_result_lbl.config(text=f"{sph:.2f}s / horde")

  def calculate_round_time(self):
    try:
      sph = float(self.rt_sph_entry.get()) if self.rt_sph_entry.get().strip() else 0.0
    except ValueError:
      return

    try:
      round_num = int(self.round_entry.get())
      players = int(self.players_spin.get())
      zombies = self.get_zombies_for_round(round_num, players)
      hordes = zombies / 24.0
    except Exception:
      hordes = 0.0

    if hordes <= 0 or sph <= 0:
      self.rt_result_lbl.config(text="0s")
      return

    total_seconds = sph * hordes
    hours = int(total_seconds // 3600)
    minutes = int((total_seconds % 3600) // 60)
    seconds = int(total_seconds % 60)

    if hours > 0:
      time_str = f"{hours}h {minutes}m {seconds}s"
    elif minutes > 0:
      time_str = f"{minutes}m {seconds}s"
    else:
      time_str = f"{seconds}s"

    self.rt_result_lbl.config(text=time_str)

  def calculate_combined_time(self):
    try:
      sph = float(self.ct_sph_entry.get()) if self.ct_sph_entry.get().strip() else 0.0
      start_r = (
          int(self.ct_start_entry.get())
          if self.ct_start_entry.get().strip()
          else 1
      )
      end_r = (
          int(self.ct_end_entry.get()) if self.ct_end_entry.get().strip() else 1
      )
    except ValueError:
      return

    if start_r > end_r or sph <= 0:
      self.ct_result_lbl.config(text="0s")
      return

    try:
      players = int(self.players_spin.get())
    except Exception:
      players = 1

    total_seconds = 0.0
    for r in range(start_r, end_r + 1):
      zombies = self.get_zombies_for_round(r, players)
      hordes = zombies / 24.0
      total_seconds += sph * hordes

    hours = int(total_seconds // 3600)
    minutes = int((total_seconds % 3600) // 60)
    seconds = int(total_seconds % 60)

    if hours > 0:
      time_str = f"{hours}h {minutes}m {seconds}s"
    elif minutes > 0:
      time_str = f"{minutes}m {seconds}s"
    else:
      time_str = f"{seconds}s"

    self.ct_result_lbl.config(text=time_str)

  def get_standard_zombies_for_round(self, n_round, n_player_count):
    zombie_max_ai = 24
    ai_per_player = 6

    multiplier = n_round / 5.0
    if multiplier < 1.0:
      multiplier = 1.0

    if n_round >= 10:
      multiplier = multiplier * (n_round * 0.15)

    if n_player_count == 1:
      max_num = zombie_max_ai + int((0.5 * ai_per_player) * multiplier)
    else:
      max_num = zombie_max_ai + int(
          ((n_player_count - 1) * ai_per_player) * multiplier
      )

    max_val = max_num
    if n_round < 2:
      max_val = int(max_num * 0.25)
    elif n_round < 3:
      max_val = int(max_num * 0.3)
    elif n_round < 4:
      max_val = int(max_num * 0.5)
    elif n_round < 5:
      max_val = int(max_num * 0.7)
    elif n_round < 6:
      max_val = int(max_num * 0.9)

    return max_val

  def get_modern_zombies_for_round(self, n_round, n_player_count):
    max_num = 24
    multiplier = min(0.075 * n_round, 4.125) * n_player_count
    zombie_ai_per_player = 3
    max_num += int(multiplier * zombie_ai_per_player * (n_round / 5.0))
    n_zombie_count = self.t10_max_zombie_func(max_num, n_round, n_player_count)
    return n_zombie_count

  def ai_calculate_health(self, base_health, round_number):
    if round_number <= 1:
      return base_health

    if round_number >= 55:
      return 50000

    zombie_health_increase = 100
    zombie_health_increase_multiplier = 0.1

    var_d082c739 = base_health

    for i in range(2, round_number + 1):
      if i >= 10:
        old_health = var_d082c739
        var_d082c739 += int(var_d082c739 * zombie_health_increase_multiplier)

        if var_d082c739 >= 50000:
          return 50000

        if var_d082c739 < old_health or var_d082c739 > 2147483647:
          var_d082c739 = old_health
          break
        continue

      var_d082c739 = int(var_d082c739 + zombie_health_increase)

    return min(var_d082c739, 50000)

  def t10_max_zombie_func(self, max_num, n_round, n_players):
    z_tospawn = [
        [6, 8, 11, 14, 17],
        [9, 11, 14, 18, 21],
        [13, 15, 20, 25, 31],
        [18, 20, 25, 33, 40],
        [24, 25, 32, 42, 48],
    ]
    if n_round <= 5:
      r_idx = min(max(n_round - 1, 0), 4)
      p_idx = min(max(n_players - 1, 0), 4)
      max_val = z_tospawn[r_idx][p_idx]
    else:
      max_val = max_num
    return max_val

  def setup_powerup_tab(self):
    title_lbl = tk.Label(
        self.power_frame,
        text="Powerup Tracker",
        font=("Death Spirit", 16),
        fg="#ff5555",
        bg="#1e1e1e",
    )
    title_lbl.pack(pady=15)
    self.accent_text_labels.append(title_lbl)

    options_frame = tk.LabelFrame(
        self.power_frame,
        text=" Optional Powerup Toggles ",
        font=("Segoe UI", 10, "bold"),
        fg="#ff5555",
        bg="#252526",
        bd=1,
        relief="solid",
    )
    options_frame.pack(padx=20, fill="x", pady=10)

    self.optional_vars = {
        "Carpenter": tk.BooleanVar(value=False),
        "Fire Sale": tk.BooleanVar(value=False),
        "Death Machine": tk.BooleanVar(value=False),
        "Zombie Blood": tk.BooleanVar(value=False),
    }

    opt_sub_frame = tk.Frame(options_frame, bg="#252526")
    opt_sub_frame.pack(padx=10, pady=6, fill="x")

    col_idx = 0
    for name, var in self.optional_vars.items():
      chk = tk.Checkbutton(
          opt_sub_frame,
          text=name,
          variable=var,
          command=self.rebuild_powerup_grid,
          font=("Segoe UI", 9),
          fg="#ffffff",
          bg="#252526",
          selectcolor="#333333",
          activebackground="#252526",
          activeforeground="#ffffff",
      )
      chk.grid(row=0, column=col_idx, sticky="w", padx=10)
      col_idx += 1

    status_frame = tk.Frame(self.power_frame, bg="#252526", padx=15, pady=8)
    status_frame.pack(padx=20, fill="x", pady=8)

    self.powerup_states = {
        "Max Ammo": False,
        "Insta-Kill": False,
        "Double Points": False,
        "Nuke": False,
        "Carpenter": False,
        "Fire Sale": False,
        "Death Machine": False,
        "Zombie Blood": False,
    }

    self.status_lbl = tk.Label(
        status_frame,
        text="Selected: 0 / 0",
        font=("Segoe UI", 11, "bold"),
        fg=self.get_accent_hex(),
        bg="#252526",
    )
    self.status_lbl.pack(side="left", pady=2)
    self.accent_text_labels.append(self.status_lbl)

    reset_btn = tk.Button(
        status_frame,
        text="Manual Reset",
        command=self.reset_powerups,
        font=("Segoe UI", 9),
        bg="#333333",
        fg="#ffffff",
        relief="flat",
        padx=8,
    )
    reset_btn.pack(side="right", pady=2)

    self.grid_container = tk.Frame(
        self.power_frame, bg="#1e1e1e", padx=5, pady=5
    )
    self.grid_container.pack(padx=10, fill="both", expand=True)

    self.card_frames = {}
    self.card_labels = {}
    self.card_icon_labels = {}
    self.rebuild_powerup_grid()

  def rebuild_powerup_grid(self):
    for widget in self.grid_container.winfo_children():
      widget.destroy()

    self.card_frames.clear()
    self.card_labels.clear()
    self.card_icon_labels.clear()

    active_powerups = ["Max Ammo", "Insta-Kill", "Double Points", "Nuke"]
    for opt_name, var in self.optional_vars.items():
      if var.get():
        active_powerups.append(opt_name)

    for col in range(4):
      self.grid_container.grid_columnconfigure(col, weight=1, uniform="equal")

    for i, name in enumerate(active_powerups):
      row = i // 4
      col = i % 4

      card = tk.Frame(
          self.grid_container,
          bg="#2d2d2d",
          bd=2,
          relief="groove",
          width=150,
          height=115,
      )
      card.grid_propagate(False)
      card.grid(row=row, column=col, padx=6, pady=6, sticky="nsew")

      inner_container = tk.Frame(card, bg="#2d2d2d")
      inner_container.place(relx=0.5, rely=0.5, anchor="center")

      img = self.loaded_images.get(name)
      if img:
        icon_lbl = tk.Label(inner_container, image=img, bg="#2d2d2d")
        icon_lbl.pack(pady=(0, 2))
        icon_lbl.bind("<Button-1>", lambda e, n=name: self.toggle_powerup(n))
        self.card_icon_labels[name] = icon_lbl

      lbl = tk.Label(
          inner_container,
          text=name,
          font=("Segoe UI", 9, "bold"),
          fg="#ffffff",
          bg="#2d2d2d",
          justify="center",
          wraplength=140,
      )
      lbl.pack()

      card.bind("<Button-1>", lambda e, n=name: self.toggle_powerup(n))
      inner_container.bind(
          "<Button-1>", lambda e, n=name: self.toggle_powerup(n)
      )
      lbl.bind("<Button-1>", lambda e, n=name: self.toggle_powerup(n))

      self.card_frames[name] = card
      self.card_labels[name] = (lbl, inner_container)

    self.update_powerup_ui()
    
    if hasattr(self, "sr_topmost_var") and self.sr_topmost_var.get():
      self.build_game_mode_trackers_display("#000002")

  def toggle_powerup(self, name):
    self.powerup_states[name] = not self.powerup_states[name]
    self.update_powerup_ui()

    enabled_powerups = ["Max Ammo", "Insta-Kill", "Double Points", "Nuke"]
    for opt_name, var in self.optional_vars.items():
      if var.get():
        enabled_powerups.append(opt_name)

    all_selected = all(
        self.powerup_states.get(p, False) for p in enabled_powerups
    )

    if all_selected:
      self.root.after(400, self.reset_powerups)

  def update_powerup_ui(self):
    enabled_powerups = ["Max Ammo", "Insta-Kill", "Double Points", "Nuke"]
    for opt_name, var in self.optional_vars.items():
      if var.get():
        enabled_powerups.append(opt_name)

    selected_count = sum(
        1 for p in enabled_powerups if self.powerup_states.get(p, False)
    )
    total_enabled = len(enabled_powerups)

    for name, card in self.card_frames.items():
      lbl, inner = self.card_labels[name]
      icon_lbl = self.card_icon_labels.get(name)

      if self.powerup_states.get(name, False):
        bg_color = self.get_accent_hex()
        card.config(bg=bg_color, bd=2, relief="solid")
      else:
        bg_color = "#2d2d2d"
        card.config(bg=bg_color, bd=2, relief="groove")

      inner.config(bg=bg_color)
      lbl.config(bg=bg_color, fg="#ffffff")
      if icon_lbl:
        icon_lbl.config(bg=bg_color)

    self.status_lbl.config(text=f"Selected: {selected_count} / {total_enabled}")

  def reset_powerups(self):
    for name in self.powerup_states:
      self.powerup_states[name] = False
    self.update_powerup_ui()
    if hasattr(self, "sr_topmost_var") and self.sr_topmost_var.get():
      self.build_game_mode_trackers_display("#000002")

  def refresh_gm_if_active(self):
    if hasattr(self, "sr_topmost_var") and self.sr_topmost_var.get():
      self.root.after(
          10, lambda: self.build_game_mode_trackers_display("#000002")
      )

  def setup_bonus_tab(self):
    self.bonus_history = []
    self.selected_excavator_location = "Tunnel 6"

    title_lbl = tk.Label(
        self.bonus_frame,
        text="Bonus Round Tracker",
        font=("Death Spirit", 16),
        fg="#ff5555",
        bg="#1e1e1e",
    )
    title_lbl.pack(pady=15)
    self.accent_text_labels.append(title_lbl)

    input_frame = tk.Frame(self.bonus_frame, bg="#252526", padx=15, pady=15)
    input_frame.pack(padx=20, fill="x")

    preset_frame = tk.Frame(input_frame, bg="#252526")
    preset_frame.grid(row=0, column=0, columnspan=2, sticky="w", pady=(0, 10))

    tk.Label(
        preset_frame,
        text="Preset:",
        font=("Segoe UI", 10, "bold"),
        fg="#ff5555",
        bg="#252526",
    ).pack(side="left", padx=(0, 8))

    self.bonus_preset_combo = ttk.Combobox(
        preset_frame,
        values=[
            "None",
            "Dogs",
            "Monkeys",
            "Spiders",
            "Shadows of Evil",
            "Der Eisendrache",
            "Gorod Krovi",
            "Revelations",
            "Excavator (Moon)",
        ],
        width=16,
        state="readonly",
    )
    self.bonus_preset_combo.pack(side="left", padx=3)
    self.bonus_preset_combo.set("None")
    self.bonus_preset_combo.bind(
        "<<ComboboxSelected>>", self.on_bonus_preset_selected
    )

    self.excavator_loc_frame = tk.Frame(input_frame, bg="#252526")
    self.excavator_loc_frame.grid(row=0, column=2, sticky="w", padx=(10, 0))

    tk.Label(
        self.excavator_loc_frame,
        text="Location:",
        font=("Segoe UI", 9, "bold"),
        fg="#d4d4d4",
        bg="#252526",
    ).pack(side="left", padx=(0, 5))

    self.excavator_loc_buttons = {}
    for loc in ["Tunnel 6", "Tunnel 11", "Biodome"]:
      btn = tk.Button(
          self.excavator_loc_frame,
          text=loc,
          command=lambda l=loc: self.set_excavator_location(l),
          font=("Segoe UI", 9, "bold"),
          bg="#2d2d2d",
          fg="#ffffff",
          activebackground="#333333",
          activeforeground="#ffffff",
          relief="flat",
          padx=8,
          pady=2,
      )
      btn.pack(side="left", padx=2)
      self.excavator_loc_buttons[loc] = btn

    self.excavator_loc_frame.grid_remove()

    tk.Label(
        input_frame,
        text="Last Bonus Round Hit:",
        font=("Segoe UI", 11),
        fg="#d4d4d4",
        bg="#252526",
    ).grid(row=1, column=0, sticky="w", pady=5)

    bonus_ctrl_frame = tk.Frame(input_frame, bg="#252526")
    bonus_ctrl_frame.grid(row=1, column=1, padx=10, sticky="w")

    self.bonus_minus_btn = tk.Button(
        bonus_ctrl_frame,
        text="-",
        command=self.decrement_bonus_round,
        font=("Segoe UI", 10, "bold"),
        bg=self.get_accent_hex(),
        fg="#ffffff",
        width=3,
        relief="flat",
    )
    self.bonus_minus_btn.pack(side="left", padx=(0, 5))
    self.accent_buttons.append(self.bonus_minus_btn)

    self.bonus_entry = tk.Entry(
        bonus_ctrl_frame,
        font=("Segoe UI", 11),
        width=5,
        bg="#333333",
        fg="#ffffff",
        insertbackground="white",
        justify="center",
    )
    self.bonus_entry.insert(0, "5")
    self.bonus_entry.pack(side="left", padx=2)
    self.bonus_entry.bind(
        "<Return>", lambda event: self.calculate_bonus_round()
    )

    self.bonus_plus_btn = tk.Button(
        bonus_ctrl_frame,
        text="+",
        command=self.increment_bonus_round,
        font=("Segoe UI", 10, "bold"),
        bg=self.get_accent_hex(),
        fg="#ffffff",
        width=3,
        relief="flat",
    )
    self.bonus_plus_btn.pack(side="left", padx=(5, 0))
    self.accent_buttons.append(self.bonus_plus_btn)

    tk.Label(
        input_frame,
        text="Interval Range (Rounds after):",
        font=("Segoe UI", 11),
        fg="#d4d4d4",
        bg="#252526",
    ).grid(row=2, column=0, sticky="w", pady=5)

    interval_frame = tk.Frame(input_frame, bg="#252526")
    interval_frame.grid(row=2, column=1, padx=10, sticky="w")

    self.bonus_min_entry = tk.Entry(
        interval_frame,
        font=("Segoe UI", 11),
        width=4,
        bg="#333333",
        fg="#ffffff",
        justify="center",
    )
    self.bonus_min_entry.insert(0, "4")
    self.bonus_min_entry.pack(side="left", padx=(0, 5))

    tk.Label(
        interval_frame,
        text="to",
        font=("Segoe UI", 10),
        fg="#d4d4d4",
        bg="#252526",
    ).pack(side="left", padx=5)

    self.bonus_max_entry = tk.Entry(
        interval_frame,
        font=("Segoe UI", 11),
        width=4,
        bg="#333333",
        fg="#ffffff",
        justify="center",
    )
    self.bonus_max_entry.insert(0, "5")
    self.bonus_max_entry.pack(side="left", padx=5)

    calc_bonus_btn = tk.Button(
        input_frame,
        text="Refresh",
        command=self.calculate_bonus_round,
        font=("Segoe UI", 10, "bold"),
        bg=self.get_accent_hex(),
        fg="#ffffff",
        relief="flat",
        padx=12,
        pady=6,
    )
    calc_bonus_btn.grid(row=3, column=0, columnspan=2, pady=15)
    self.accent_buttons.append(calc_bonus_btn)

    bonus_output_frame = tk.Frame(
        self.bonus_frame, bg="#252526", padx=15, pady=15
    )
    bonus_output_frame.pack(padx=20, pady=15, fill="both", expand=True)

    tk.Label(
        bonus_output_frame,
        text="Next bonus round:",
        font=("Segoe UI", 11, "bold"),
        fg="#ff5555",
        bg="#252526",
        anchor="w",
    ).pack(fill="x", pady=(0, 8))

    self.bonus_buttons_container = tk.Frame(bonus_output_frame, bg="#252526")
    self.bonus_buttons_container.pack(fill="x", pady=5)

    hist_frame = tk.Frame(self.bonus_frame, bg="#1e1e1e", padx=5, pady=5)
    hist_frame.pack(padx=20, fill="x", pady=5)

    hist_top_frame = tk.Frame(hist_frame, bg="#1e1e1e")
    hist_top_frame.pack(fill="x", pady=(0, 2))

    tk.Label(
        hist_top_frame,
        text="History:",
        font=("Segoe UI", 10, "bold"),
        fg="#ff5555",
        bg="#1e1e1e",
    ).pack(side="left")

    hist_btns_right = tk.Frame(hist_top_frame, bg="#1e1e1e")
    hist_btns_right.pack(side="right")

    undo_bonus_btn = tk.Button(
        hist_btns_right,
        text="Undo",
        command=self.undo_bonus_round,
        font=("Segoe UI", 9),
        bg="#333333",
        fg="#ffffff",
        relief="flat",
        padx=6,
    )
    undo_bonus_btn.pack(side="left", padx=(0, 4))

    reset_bonus_hist_btn = tk.Button(
        hist_btns_right,
        text="Reset History",
        command=self.reset_bonus_history,
        font=("Segoe UI", 9),
        bg="#333333",
        fg="#ffffff",
        relief="flat",
        padx=6,
    )
    reset_bonus_hist_btn.pack(side="left")

    self.bonus_history_lbl = tk.Label(
        hist_frame,
        text="None",
        font=("Segoe UI", 10),
        fg="#858585",
        bg="#1e1e1e",
        anchor="w",
        justify="left",
        wraplength=680,
    )
    self.bonus_history_lbl.pack(fill="x", expand=True)

    self.update_excavator_buttons_ui()

  def undo_bonus_round(self):
    if len(self.bonus_history) > 1:
      self.bonus_history.pop()
      last_item = self.bonus_history[-1]
      last_rnd = (
          last_item["round"] if isinstance(last_item, dict) else last_item
      )

      self.bonus_entry.delete(0, tk.END)
      self.bonus_entry.insert(0, str(last_rnd))

      if isinstance(last_item, dict) and last_item.get("location"):
        self.selected_excavator_location = last_item["location"]
        self.update_excavator_buttons_ui()

      self.update_bonus_history_display()
      self.calculate_bonus_round()
      self.calculate_zombies()
      self.refresh_gm_if_active()
    elif len(self.bonus_history) == 1:
      self.reset_bonus_history()

  def set_excavator_location(self, loc):
    self.selected_excavator_location = loc
    self.update_excavator_buttons_ui()
    self.refresh_gm_if_active()

  def update_excavator_buttons_ui(self):
    accent_hex = self.get_accent_hex()
    for loc, btn in self.excavator_loc_buttons.items():
      if loc == self.selected_excavator_location:
        btn.config(bg=accent_hex, fg="#ffffff")
      else:
        btn.config(bg="#2d2d2d", fg="#ffffff")

  def on_bonus_preset_selected(self, event):
    selection = self.bonus_preset_combo.get()
    try:
      players = int(self.players_spin.get())
    except Exception:
      players = 1

    if selection == "Excavator (Moon)":
      self.excavator_loc_frame.grid()
    else:
      self.excavator_loc_frame.grid_remove()

    if selection == "None":
      self.apply_bonus_preset(5, 4, 5)
    elif selection in ["Dogs", "Spiders"]:
      self.apply_bonus_preset(5, 4, 5)
    elif selection == "Monkeys":
      self.apply_bonus_preset(5, 4, 5)
    elif selection == "Shadows of Evil":
      self.apply_bonus_preset(5, 5, 9)
    elif selection == "Der Eisendrache":
      self.apply_bonus_preset(5, 7, 13)
    elif selection == "Gorod Krovi":
      start_rnd = 12 if players == 1 else 9
      self.apply_bonus_preset(start_rnd, 7, 9)
    elif selection == "Revelations":
      self.apply_bonus_preset(5, 9, 10)
    elif selection == "Excavator (Moon)":
      self.apply_bonus_preset(1, 2, 8)

  def apply_bonus_preset(self, start_rnd, min_int, max_int):
    self.bonus_entry.delete(0, tk.END)
    self.bonus_entry.insert(0, str(start_rnd))

    self.bonus_min_entry.delete(0, tk.END)
    self.bonus_min_entry.insert(0, str(min_int))

    self.bonus_max_entry.delete(0, tk.END)
    self.bonus_max_entry.insert(0, str(max_int))

    self.bonus_history = [{
        "round": start_rnd,
        "preset": self.bonus_preset_combo.get(),
        "location": (
            self.selected_excavator_location
            if self.bonus_preset_combo.get() == "Excavator (Moon)"
            else None
        ),
    }]
    self.update_bonus_history_display()
    self.calculate_bonus_round()
    self.calculate_zombies()
    self.refresh_gm_if_active()

  def increment_bonus_round(self):
    try:
      val = int(self.bonus_entry.get())
    except ValueError:
      val = 0
    self.bonus_entry.delete(0, tk.END)
    self.bonus_entry.insert(0, str(val + 1))
    self.calculate_bonus_round()

  def decrement_bonus_round(self):
    try:
      val = int(self.bonus_entry.get())
    except ValueError:
      val = 2
    if val > 1:
      self.bonus_entry.delete(0, tk.END)
      self.bonus_entry.insert(0, str(val - 1))
      self.calculate_bonus_round()

  def calculate_bonus_round(self):
    preset = self.bonus_preset_combo.get()
    location = (
        self.selected_excavator_location if preset == "Excavator (Moon)" else None
    )

    if preset == "None":
      for widget in self.bonus_buttons_container.winfo_children():
        widget.destroy()
      tk.Label(
          self.bonus_buttons_container,
          text="No bonus rounds for this preset.",
          font=("Segoe UI", 10),
          fg="#858585",
          bg="#252526",
      ).pack(side="left", padx=5)
      self.bonus_history = []
      self.update_bonus_history_display()
      self.calculate_zombies()
      self.refresh_gm_if_active()
      return

    try:
      last_round = int(self.bonus_entry.get())
      min_int = int(self.bonus_min_entry.get())
      max_int = int(self.bonus_max_entry.get())
    except ValueError:
      messagebox.showerror(
          "Invalid Input", "Please enter valid numeric values for rounds."
      )
      return

    if not self.bonus_history:
      self.bonus_history = [{
          "round": last_round,
          "preset": preset,
          "location": location,
      }]
    else:
      if isinstance(self.bonus_history[-1], dict):
        self.bonus_history[-1]["round"] = last_round
        self.bonus_history[-1]["preset"] = preset
        self.bonus_history[-1]["location"] = location
      else:
        self.bonus_history[-1] = last_round

    self.update_bonus_history_display()

    next_min = last_round + min_int
    next_max = last_round + max_int

    for widget in self.bonus_buttons_container.winfo_children():
      widget.destroy()

    for r in range(next_min, next_max + 1):
      btn = tk.Button(
          self.bonus_buttons_container,
          text=f"{r}",
          command=lambda r_val=r: self.select_bonus_round(r_val),
          font=("Segoe UI", 11, "bold"),
          bg=self.get_accent_hex(),
          fg="#ffffff",
          relief="flat",
          width=5,
          pady=8,
      )
      btn.pack(side="left", padx=5)
      self.accent_buttons.append(btn)

    self.calculate_zombies()
    self.refresh_gm_if_active()

  def select_bonus_round(self, round_val):
    preset = self.bonus_preset_combo.get()
    location = (
        self.selected_excavator_location if preset == "Excavator (Moon)" else None
    )
    self.bonus_history.append(
        {"round": round_val, "preset": preset, "location": location}
    )
    self.bonus_entry.delete(0, tk.END)
    self.bonus_entry.insert(0, str(round_val))
    self.update_bonus_history_display()
    self.calculate_bonus_round()
    self.calculate_zombies()
    self.refresh_gm_if_active()

  def update_bonus_history_display(self):
    if not self.bonus_history or self.bonus_preset_combo.get() == "None":
      self.bonus_history_lbl.config(text="None")
      return

    formatted_items = []
    for item in self.bonus_history:
      if isinstance(item, dict):
        r_str = str(item["round"])
        loc = item.get("location")
        if loc:
          formatted_items.append(f"{r_str} ({loc})")
        else:
          formatted_items.append(r_str)
      else:
        formatted_items.append(str(item))

    hist_str = " → ".join(formatted_items)
    self.bonus_history_lbl.config(text=hist_str)

  def reset_bonus_history(self):
    self.bonus_history.clear()
    self.on_bonus_preset_selected(None)
    self.calculate_zombies()
    self.refresh_gm_if_active()

  def setup_boss_tab(self):
    self.boss_history = []

    title_lbl = tk.Label(
        self.boss_frame,
        text="Boss Round Tracker",
        font=("Death Spirit", 16),
        fg="#ff5555",
        bg="#1e1e1e",
    )
    title_lbl.pack(pady=15)
    self.accent_text_labels.append(title_lbl)

    input_frame = tk.Frame(self.boss_frame, bg="#252526", padx=15, pady=15)
    input_frame.pack(padx=20, fill="x")

    boss_preset_frame = tk.Frame(input_frame, bg="#252526")
    boss_preset_frame.grid(
        row=0, column=0, columnspan=2, sticky="w", pady=(0, 10)
    )

    tk.Label(
        boss_preset_frame,
        text="Preset:",
        font=("Segoe UI", 10, "bold"),
        fg="#ff5555",
        bg="#252526",
    ).pack(side="left", padx=(0, 8))

    self.boss_preset_combo = ttk.Combobox(
        boss_preset_frame,
        values=[
            "None",
            "Origins",
            "Mob of the Dead",
            "Shadows of Evil",
            "Der Eisendrache",
            "Zetsubou No Shima",
            "Revelations",
        ],
        width=18,
        state="readonly",
    )
    self.boss_preset_combo.pack(side="left", padx=3)
    self.boss_preset_combo.set("None")
    self.boss_preset_combo.bind(
        "<<ComboboxSelected>>", self.on_boss_preset_selected
    )

    tk.Label(
        input_frame,
        text="Last Boss Round Hit:",
        font=("Segoe UI", 11),
        fg="#d4d4d4",
        bg="#252526",
    ).grid(row=1, column=0, sticky="w", pady=5)

    boss_ctrl_frame = tk.Frame(input_frame, bg="#252526")
    boss_ctrl_frame.grid(row=1, column=1, padx=10, sticky="w")

    self.boss_minus_btn = tk.Button(
        boss_ctrl_frame,
        text="-",
        command=self.decrement_boss_round,
        font=("Segoe UI", 10, "bold"),
        bg=self.get_accent_hex(),
        fg="#ffffff",
        width=3,
        relief="flat",
    )
    self.boss_minus_btn.pack(side="left", padx=(0, 5))
    self.accent_buttons.append(self.boss_minus_btn)

    self.boss_entry = tk.Entry(
        boss_ctrl_frame,
        font=("Segoe UI", 11),
        width=5,
        bg="#333333",
        fg="#ffffff",
        insertbackground="white",
        justify="center",
    )
    self.boss_entry.insert(0, "8")
    self.boss_entry.pack(side="left", padx=2)
    self.boss_entry.bind(
        "<Return>", lambda event: self.calculate_boss_round()
    )

    self.boss_plus_btn = tk.Button(
        boss_ctrl_frame,
        text="+",
        command=self.increment_boss_round,
        font=("Segoe UI", 10, "bold"),
        bg=self.get_accent_hex(),
        fg="#ffffff",
        width=3,
        relief="flat",
    )
    self.boss_plus_btn.pack(side="left", padx=(5, 0))
    self.accent_buttons.append(self.boss_plus_btn)

    tk.Label(
        input_frame,
        text="Interval Range (Rounds after):",
        font=("Segoe UI", 11),
        fg="#d4d4d4",
        bg="#252526",
    ).grid(row=2, column=0, sticky="w", pady=5)

    boss_int_frame = tk.Frame(input_frame, bg="#252526")
    boss_int_frame.grid(row=2, column=1, padx=10, sticky="w")

    self.boss_min_entry = tk.Entry(
        boss_int_frame,
        font=("Segoe UI", 11),
        width=4,
        bg="#333333",
        fg="#ffffff",
        justify="center",
    )
    self.boss_min_entry.insert(0, "4")
    self.boss_min_entry.pack(side="left", padx=(0, 5))

    tk.Label(
        boss_int_frame,
        text="to",
        font=("Segoe UI", 10),
        fg="#d4d4d4",
        bg="#252526",
    ).pack(side="left", padx=5)

    self.boss_max_entry = tk.Entry(
        boss_int_frame,
        font=("Segoe UI", 11),
        width=4,
        bg="#333333",
        fg="#ffffff",
        justify="center",
    )
    self.boss_max_entry.insert(0, "5")
    self.boss_max_entry.pack(side="left", padx=5)

    calc_boss_btn = tk.Button(
        input_frame,
        text="Refresh",
        command=self.calculate_boss_round,
        font=("Segoe UI", 10, "bold"),
        bg=self.get_accent_hex(),
        fg="#ffffff",
        relief="flat",
        padx=12,
        pady=6,
    )
    calc_boss_btn.grid(row=3, column=0, columnspan=2, pady=15)
    self.accent_buttons.append(calc_boss_btn)

    boss_output_frame = tk.Frame(
        self.boss_frame, bg="#252526", padx=15, pady=15
    )
    boss_output_frame.pack(padx=20, pady=15, fill="both", expand=True)

    tk.Label(
        boss_output_frame,
        text="Next boss round:",
        font=("Segoe UI", 11, "bold"),
        fg="#ff5555",
        bg="#252526",
        anchor="w",
    ).pack(fill="x", pady=(0, 8))

    self.boss_buttons_container = tk.Frame(boss_output_frame, bg="#252526")
    self.boss_buttons_container.pack(fill="x", pady=5)

    boss_hist_frame = tk.Frame(self.boss_frame, bg="#1e1e1e", padx=5, pady=5)
    boss_hist_frame.pack(padx=20, fill="x", pady=5)

    boss_hist_top_frame = tk.Frame(boss_hist_frame, bg="#1e1e1e")
    boss_hist_top_frame.pack(fill="x", pady=(0, 2))

    tk.Label(
        boss_hist_top_frame,
        text="History:",
        font=("Segoe UI", 10, "bold"),
        fg="#ff5555",
        bg="#1e1e1e",
    ).pack(side="left")

    boss_hist_btns_right = tk.Frame(boss_hist_top_frame, bg="#1e1e1e")
    boss_hist_btns_right.pack(side="right")

    undo_boss_btn = tk.Button(
        boss_hist_btns_right,
        text="Undo",
        command=self.undo_boss_round,
        font=("Segoe UI", 9),
        bg="#333333",
        fg="#ffffff",
        relief="flat",
        padx=6,
    )
    undo_boss_btn.pack(side="left", padx=(0, 4))

    reset_boss_hist_btn = tk.Button(
        boss_hist_btns_right,
        text="Reset History",
        command=self.reset_boss_history,
        font=("Segoe UI", 9),
        bg="#333333",
        fg="#ffffff",
        relief="flat",
        padx=6,
    )
    reset_boss_hist_btn.pack(side="left")

    self.boss_history_lbl = tk.Label(
        boss_hist_frame,
        text="None",
        font=("Segoe UI", 10),
        fg="#858585",
        bg="#1e1e1e",
        anchor="w",
        justify="left",
        wraplength=680,
    )
    self.boss_history_lbl.pack(fill="x", expand=True)

    self.on_boss_preset_selected(None)

  def undo_boss_round(self):
    if len(self.boss_history) > 1:
      self.boss_history.pop()
      last_rnd = self.boss_history[-1]

      self.boss_entry.delete(0, tk.END)
      self.boss_entry.insert(0, str(last_rnd))

      self.update_boss_history_display()
      self.calculate_boss_round()
      self.refresh_gm_if_active()
    elif len(self.boss_history) == 1:
      self.reset_boss_history()

  def on_boss_preset_selected(self, event=None):
    selection = self.boss_preset_combo.get()
    if selection == "None":
      self.apply_boss_preset(8, 4, 5)
    elif selection == "Origins":
      self.apply_boss_preset(8, 4, 5)
    elif selection == "Mob of the Dead":
      self.apply_boss_preset(9, 4, 6)
    elif selection == "Shadows of Evil":
      self.apply_boss_preset(8, 5, 7)
    elif selection == "Der Eisendrache":
      self.apply_boss_preset(12, 5, 7)
    elif selection == "Zetsubou No Shima":
      self.apply_boss_preset(7, 3, 4)
    elif selection == "Revelations":
      self.apply_boss_preset(11, 7, 11)

  def apply_boss_preset(self, start_rnd, min_int, max_int):
    self.boss_entry.delete(0, tk.END)
    self.boss_entry.insert(0, str(start_rnd))

    self.boss_min_entry.delete(0, tk.END)
    self.boss_min_entry.insert(0, str(min_int))

    self.boss_max_entry.delete(0, tk.END)
    self.boss_max_entry.insert(0, str(max_int))

    self.boss_history = [start_rnd]
    self.update_boss_history_display()
    self.calculate_boss_round()
    self.refresh_gm_if_active()

  def increment_boss_round(self):
    try:
      val = int(self.boss_entry.get())
    except ValueError:
      val = 0
    self.boss_entry.delete(0, tk.END)
    self.boss_entry.insert(0, str(val + 1))
    self.calculate_boss_round()

  def decrement_boss_round(self):
    try:
      val = int(self.boss_entry.get())
    except ValueError:
      val = 2
    if val > 1:
      self.boss_entry.delete(0, tk.END)
      self.boss_entry.insert(0, str(val - 1))
      self.calculate_boss_round()

  def calculate_boss_round(self):
    preset = self.boss_preset_combo.get()

    if preset == "None":
      for widget in self.boss_buttons_container.winfo_children():
        widget.destroy()
      tk.Label(
          self.boss_buttons_container,
          text="No boss rounds for this preset.",
          font=("Segoe UI", 10),
          fg="#858585",
          bg="#252526",
      ).pack(side="left", padx=5)
      self.boss_history = []
      self.update_boss_history_display()
      self.refresh_gm_if_active()
      return

    try:
      last_round = int(self.boss_entry.get())
      min_int = int(self.boss_min_entry.get())
      max_int = int(self.boss_max_entry.get())
    except ValueError:
      messagebox.showerror(
          "Invalid Input", "Please enter valid numeric values for boss rounds."
      )
      return

    if not self.boss_history:
      self.boss_history = [last_round]
    else:
      self.boss_history[-1] = last_round

    self.update_boss_history_display()

    next_min = last_round + min_int
    next_max = last_round + max_int

    for widget in self.boss_buttons_container.winfo_children():
      widget.destroy()

    for r in range(next_min, next_max + 1):
      btn = tk.Button(
          self.boss_buttons_container,
          text=f"{r}",
          command=lambda r_val=r: self.select_boss_round(r_val),
          font=("Segoe UI", 11, "bold"),
          bg=self.get_accent_hex(),
          fg="#ffffff",
          relief="flat",
          width=5,
          pady=8,
      )
      btn.pack(side="left", padx=5)
      self.accent_buttons.append(btn)

    self.refresh_gm_if_active()

  def select_boss_round(self, round_val):
    self.boss_history.append(round_val)
    self.boss_entry.delete(0, tk.END)
    self.boss_entry.insert(0, str(round_val))
    self.update_boss_history_display()
    self.calculate_boss_round()
    self.refresh_gm_if_active()

  def update_boss_history_display(self):
    if not self.boss_history or self.boss_preset_combo.get() == "None":
      self.boss_history_lbl.config(text="None")
      return
    hist_str = " → ".join(map(str, self.boss_history))
    self.boss_history_lbl.config(text=hist_str)

  def reset_boss_history(self):
    self.boss_history.clear()
    self.on_boss_preset_selected(None)
    self.refresh_gm_if_active()

  def setup_gum_combined_tab(self):
    title_lbl = tk.Label(
        self.gum_combined_frame,
        text="GobbleGum Pack & Tracker",
        font=("Death Spirit", 16),
        fg="#ff5555",
        bg="#1e1e1e",
    )
    title_lbl.pack(pady=10)
    self.accent_text_labels.append(title_lbl)

    self.setup_section = tk.Frame(
        self.gum_combined_frame, bg="#252526", padx=10, pady=10
    )
    self.setup_section.pack(padx=20, fill="x", pady=5)

    setup_header = tk.Frame(self.setup_section, bg="#252526")
    setup_header.pack(fill="x", padx=5, pady=(0, 6))

    tk.Label(
        setup_header,
        text="Pack Setup (Click slot to choose gum):",
        font=("Segoe UI", 9, "bold"),
        fg="#d4d4d4",
        bg="#252526",
    ).pack(side="left")

    self.toggle_setup_btn = tk.Button(
        setup_header,
        text="▼ Hide Pack Setup",
        command=self.toggle_setup_section,
        font=("Segoe UI", 8),
        bg="#333333",
        fg="#ffffff",
        relief="flat",
        padx=6,
        pady=1,
    )
    self.toggle_setup_btn.pack(side="right")

    self.setup_body = tk.Frame(self.setup_section, bg="#252526")
    self.setup_body.pack(fill="x", pady=(2, 0))

    slots_outer = tk.Frame(self.setup_body, bg="#252526")
    slots_outer.pack(fill="x")

    self.slot_buttons = []
    for i in range(5):
      slot_frame = tk.Frame(
          slots_outer, bg="#2d2d2d", bd=2, relief="groove", width=105, height=115
      )
      slot_frame.pack_propagate(False)
      slot_frame.pack(side="left", padx=4, expand=True)

      btn = tk.Button(
          slot_frame,
          text=f"Slot {i+1}\n(Empty)",
          command=lambda idx=i: self.open_gum_selector(idx),
          font=("Segoe UI", 9, "bold"),
          bg="#2d2d2d",
          fg="#ffffff",
          activebackground="#333333",
          activeforeground="#ffffff",
          relief="flat",
          cursor="hand2",
      )
      btn.pack(fill="both", expand=True)
      self.slot_buttons.append(btn)

    clear_pack_btn = tk.Button(
        self.setup_body,
        text="Clear Pack",
        command=self.clear_gum_pack,
        font=("Segoe UI", 8, "bold"),
        bg="#333333",
        fg="#ffffff",
        relief="flat",
        padx=10,
        pady=3,
    )
    clear_pack_btn.pack(pady=(8, 2))

    tracker_section = tk.Frame(
        self.gum_combined_frame, bg="#252526", padx=10, pady=10
    )
    tracker_section.pack(padx=20, fill="both", expand=True, pady=5)

    tracker_header = tk.Frame(tracker_section, bg="#252526")
    tracker_header.pack(fill="x", pady=(0, 6))

    self.gum_tracker_status_lbl = tk.Label(
        tracker_header,
        text="Selected: 0 / 5",
        font=("Segoe UI", 10, "bold"),
        fg=self.get_accent_hex(),
        bg="#252526",
    )
    self.gum_tracker_status_lbl.pack(side="left")
    self.accent_text_labels.append(self.gum_tracker_status_lbl)

    reset_tracker_btn = tk.Button(
        tracker_header,
        text="Manual Reset",
        command=self.reset_gum_tracker,
        font=("Segoe UI", 8),
        bg="#333333",
        fg="#ffffff",
        relief="flat",
        padx=8,
        pady=2,
    )
    reset_tracker_btn.pack(side="right")

    self.gum_grid_container = tk.Frame(
        tracker_section, bg="#1e1e1e", padx=5, pady=5
    )
    self.gum_grid_container.pack(fill="both", expand=True)

    self.rebuild_gum_tracker_grid()

  def toggle_setup_section(self):
    if self.setup_visible:
      self.setup_body.pack_forget()
      self.toggle_setup_btn.config(text="▶ Show Pack Setup")
      self.setup_visible = False
    else:
      self.setup_body.pack(fill="x", pady=(2, 0))
      self.toggle_setup_btn.config(text="▼ Hide Pack Setup")
      self.setup_visible = True

  def rebuild_gum_tracker_grid(self):
    for widget in self.gum_grid_container.winfo_children():
      widget.destroy()

    self.gum_card_frames = {}
    self.gum_card_labels = {}
    self.gum_card_icon_labels = {}

    active_gums = [g for g in self.selected_gums if g is not None]

    if len(active_gums) < 5:
      msg_lbl = tk.Label(
          self.gum_grid_container,
          text=(
              "Please select all 5 GobbleGum pack slots to unlock the"
              " tracker!\n(Currently filled:"
              f" {len(active_gums)} / 5)"
          ),
          font=("Segoe UI", 10),
          fg="#858585",
          bg="#1e1e1e",
          justify="center",
      )
      msg_lbl.pack(pady=40)
      self.gum_tracker_status_lbl.config(text="Selected: 0 / 5")
      self.auto_compressed = False
      return

    if not self.auto_compressed and self.setup_visible:
      self.toggle_setup_section()
      self.auto_compressed = True

    for col in range(5):
      self.gum_grid_container.grid_columnconfigure(
          col, weight=1, uniform="equal"
      )

    for i, name in enumerate(active_gums):
      row = i // 5
      col = i % 5

      card = tk.Frame(
          self.gum_grid_container,
          bg="#2d2d2d",
          bd=2,
          relief="groove",
          width=115,
          height=110,
      )
      card.grid_propagate(False)
      card.grid(row=row, column=col, padx=4, pady=4, sticky="nsew")

      inner_container = tk.Frame(card, bg="#2d2d2d")
      inner_container.place(relx=0.5, rely=0.5, anchor="center")

      img = self.gum_loaded_images.get(name)
      if img:
        icon_lbl = tk.Label(inner_container, image=img, bg="#2d2d2d")
        icon_lbl.pack(pady=(0, 2))
        icon_lbl.bind(
            "<Button-1>", lambda e, n=name: self.toggle_gum_tracker(n)
        )
        self.gum_card_icon_labels[name] = icon_lbl

      lbl = tk.Label(
          inner_container,
          text=name,
          font=("Segoe UI", 8, "bold"),
          fg="#ffffff",
          bg="#2d2d2d",
          justify="center",
          wraplength=105,
      )
      lbl.pack()

      card.bind("<Button-1>", lambda e, n=name: self.toggle_gum_tracker(n))
      inner_container.bind(
          "<Button-1>", lambda e, n=name: self.toggle_gum_tracker(n)
      )
      lbl.bind("<Button-1>", lambda e, n=name: self.toggle_gum_tracker(n))

      self.gum_card_frames[name] = card
      self.gum_card_labels[name] = (lbl, inner_container)

      if name not in self.gum_tracker_states:
        self.gum_tracker_states[name] = False

    self.update_gum_tracker_ui()

  def toggle_gum_tracker(self, name):
    self.gum_tracker_states[name] = not self.gum_tracker_states.get(
        name, False
    )
    self.update_gum_tracker_ui()

    active_gums = [g for g in self.selected_gums if g is not None]
    if len(active_gums) == 5 and all(
        self.gum_tracker_states.get(g, False) for g in active_gums
    ):
      self.root.after(400, self.reset_gum_tracker)

  def update_gum_tracker_ui(self):
    active_gums = [g for g in self.selected_gums if g is not None]
    if len(active_gums) < 5:
      return

    selected_count = sum(
        1 for g in active_gums if self.gum_tracker_states.get(g, False)
    )
    total_enabled = len(active_gums)

    for name, card in self.gum_card_frames.items():
      lbl, inner = self.gum_card_labels[name]
      icon_lbl = self.gum_card_icon_labels.get(name)

      if self.gum_tracker_states.get(name, False):
        bg_color = self.get_accent_hex()
        card.config(bg=bg_color, bd=2, relief="solid")
      else:
        bg_color = "#2d2d2d"
        card.config(bg=bg_color, bd=2, relief="groove")

      inner.config(bg=bg_color)
      lbl.config(bg=bg_color, fg="#ffffff")
      if icon_lbl:
        icon_lbl.config(bg=bg_color)

    self.gum_tracker_status_lbl.config(
        text=f"Selected: {selected_count} / {total_enabled}"
    )

  def reset_gum_tracker(self):
    for name in self.gum_tracker_states:
      self.gum_tracker_states[name] = False
    self.update_gum_tracker_ui()
    if hasattr(self, "sr_topmost_var") and self.sr_topmost_var.get():
      self.build_game_mode_trackers_display("#000002")

  def open_gum_selector(self, slot_index):
    selector_win = tk.Toplevel(self.root)
    selector_win.title(f"Select GobbleGum for Slot {slot_index + 1}")
    selector_win.geometry("540x580")

    self.root.update_idletasks()
    main_x = self.root.winfo_rootx()
    main_y = self.root.winfo_rooty()
    main_w = self.root.winfo_width()
    main_h = self.root.winfo_height()

    popup_w, popup_h = 540, 580
    pos_x = main_x + (main_w - popup_w) // 2
    pos_y = main_y + (main_h - popup_h) // 2
    selector_win.geometry(f"{popup_w}x{popup_h}+{pos_x}+{pos_y}")

    selector_win.configure(bg="#1e1e1e")
    selector_win.transient(self.root)
    selector_win.grab_set()

    tk.Label(
        selector_win,
        text=f"Choose a GobbleGum for Slot {slot_index + 1}:",
        font=("Segoe UI", 11, "bold"),
        fg="#ff5555",
        bg="#1e1e1e",
    ).pack(pady=(12, 6))

    popup_tab_bar = tk.Frame(selector_win, bg="#1e1e1e")
    popup_tab_bar.pack(fill="x", padx=15, pady=(0, 10))

    popup_content_container = tk.Frame(selector_win, bg="#1e1e1e")
    popup_content_container.pack(
        fill="both", expand=True, padx=15, pady=(0, 15)
    )

    categories = [
        ("Classics", self.classic_gums),
        ("Megas", self.mega_gums),
        ("Whimsicals", self.whimsical_gums),
    ]

    tab_frames = []
    tab_buttons = []
    canvases = []

    def show_popup_page(page_index):
      for idx, f in enumerate(tab_frames):
        if idx == page_index:
          f.pack(fill="both", expand=True)
          canvases[idx].update_idletasks()
          canvases[idx].configure(scrollregion=canvases[idx].bbox("all"))
        else:
          f.pack_forget()

      for idx, btn in enumerate(tab_buttons):
        if idx == page_index:
          btn.config(bg=self.get_accent_hex())
        else:
          btn.config(bg="#2d2d2d")

    def _on_mousewheel(event):
      for c in canvases:
        if c.winfo_ismapped():
          try:
            amount = -int(event.delta / 120) * 4
            c.yview_scroll(amount, "units")
          except Exception:
            pass
          break

    selector_win.bind_all("<MouseWheel>", _on_mousewheel)

    for idx, (cat_name, gum_dict) in enumerate(categories):
      tab_frame = tk.Frame(popup_content_container, bg="#1e1e1e")
      tab_frames.append(tab_frame)

      container = tk.Frame(tab_frame, bg="#1e1e1e")
      container.pack(fill="both", expand=True)

      canvas = tk.Canvas(container, bg="#1e1e1e", highlightthickness=0)
      canvases.append(canvas)
      scrollbar = ttk.Scrollbar(
          container, orient="vertical", command=canvas.yview
      )
      scrollable_frame = tk.Frame(canvas, bg="#1e1e1e")

      scrollable_frame.bind(
          "<Configure>",
          lambda e, canv=canvas, sf=scrollable_frame: canv.configure(
              scrollregion=(0, 0, sf.winfo_reqwidth(), sf.winfo_reqheight())
          ),
      )

      window_id = canvas.create_window(
          (0, 0), window=scrollable_frame, anchor="nw"
      )

      canvas.bind(
          "<Configure>",
          lambda e, canv=canvas, win_id=window_id: canv.itemconfig(
              win_id, width=e.width
          ),
      )

      canvas.configure(yscrollcommand=scrollbar.set)

      canvas.pack(side="left", fill="both", expand=True)
      scrollbar.pack(side="right", fill="y")

      col_count = 3
      for g_idx, gum_name in enumerate(gum_dict.keys()):
        r = g_idx // col_count
        c = g_idx % col_count

        is_already_used = gum_name in self.selected_gums
        btn_bg = "#2d2d2d" if not is_already_used else "#252526"
        fg_color = "#ffffff" if not is_already_used else "#555555"

        img = self.gum_loaded_images.get(gum_name)

        gum_btn = tk.Button(
            scrollable_frame,
            text=gum_name,
            image=img if img else "",
            compound="top" if img else "none",
            command=lambda name=gum_name, used=is_already_used, win=selector_win: [
                selector_win.unbind_all("<MouseWheel>"),
                self.assign_gum(slot_index, name, used, win),
            ],
            font=("Segoe UI", 9, "bold"),
            bg=btn_bg,
            fg=fg_color,
            activebackground=self.get_accent_hex(),
            activeforeground="#ffffff",
            relief="flat",
            width=140,
            height=85,
            cursor="hand2" if not is_already_used else "arrow",
        )
        gum_btn.grid(row=r, column=c, padx=6, pady=6, sticky="n")

      for col_idx in range(col_count):
        scrollable_frame.grid_columnconfigure(col_idx, weight=1)

      scrollable_frame.update_idletasks()
      canvas.configure(scrollregion=canvas.bbox("all"))

      tab_btn = tk.Button(
          popup_tab_bar,
          text=f"  {cat_name}  ",
          font=("Segoe UI", 10, "bold"),
          fg="#ffffff",
          activeforeground="#ffffff",
          bg="#2d2d2d",
          activebackground=self.get_accent_hex(),
          relief="flat",
          bd=0,
          padx=10,
          pady=6,
          command=lambda i=idx: show_popup_page(i),
      )
      tab_btn.pack(side="left", expand=True, fill="x", padx=3)
      tab_buttons.append(tab_btn)

    show_popup_page(0)

    def on_closing():
      selector_win.unbind_all("<MouseWheel>")
      if hasattr(self, "calc_canvas") and self.pages[0].winfo_ismapped():
        self.calc_canvas.bind_all("<MouseWheel>", self._on_calc_mousewheel)
      selector_win.destroy()

    selector_win.protocol("WM_DELETE_WINDOW", on_closing)

  def assign_gum(self, slot_index, gum_name, is_already_used, window):
    if is_already_used:
      messagebox.showwarning(
          "Duplicate Gum",
          f'"{gum_name}" is already in your pack! Each gum must be unique.',
          parent=window,
      )
      return

    self.selected_gums[slot_index] = gum_name
    self.save_config()
    window.destroy()
    
    if hasattr(self, "calc_canvas") and self.pages[0].winfo_ismapped():
      self.calc_canvas.bind_all("<MouseWheel>", self._on_calc_mousewheel)
    
    self.update_gum_ui()
    self.rebuild_gum_tracker_grid()

  def clear_gum_pack(self):
    self.selected_gums = [None, None, None, None, None]
    self.auto_compressed = False
    self.update_gum_ui()
    if not self.setup_visible:
      self.toggle_setup_section()
    self.rebuild_gum_tracker_grid()
    self.save_config()

  def update_gum_ui(self):
    for i, gum_name in enumerate(self.selected_gums):
      btn = self.slot_buttons[i]
      if gum_name:
        img = self.gum_loaded_images.get(gum_name)
        btn.config(
            text=f"{gum_name}",
            image=img if img else "",
            compound="top" if img else "none",
            bg=self.get_accent_hex(),
            fg="#ffffff",
            wraplength=95,
        )
      else:
        btn.config(
            text=f"Slot {i+1}\n(Empty)",
            image="",
            compound="none",
            bg="#2d2d2d",
            fg="#ffffff",
            wraplength=95,
        )

  def setup_speedrun_tab(self):
    self.sr_title_lbl = tk.Label(
        self.speedrun_frame,
        text="GAME TIME & ROUND SPLITS",
        font=("Death Spirit", 16),
        fg="#ff5555",
        bg="#1e1e1e",
    )
    self.sr_title_lbl.pack(pady=(10, 5))
    self.accent_text_labels.append(self.sr_title_lbl)

    self.sr_ctrl_panel = tk.Frame(
        self.speedrun_frame, bg="#252526", padx=12, pady=8
    )
    self.sr_ctrl_panel.pack(padx=15, fill="x", pady=5)

    self.sr_btn_row = tk.Frame(self.sr_ctrl_panel, bg="#252526")
    self.sr_btn_row.pack(fill="x", pady=(0, 5))

    self.sr_start_btn = tk.Button(
        self.sr_btn_row,
        text="Start / Split",
        command=self.sr_split_action,
        font=("Segoe UI", 9, "bold"),
        bg=self.get_accent_hex(),
        fg="#ffffff",
        relief="flat",
        padx=12,
        pady=4,
    )
    self.sr_start_btn.pack(side="left", padx=3)
    self.accent_buttons.append(self.sr_start_btn)

    sr_reset_btn = tk.Button(
        self.sr_btn_row,
        text="Reset",
        command=self.sr_reset_timer,
        font=("Segoe UI", 9),
        bg="#333333",
        fg="#ffffff",
        relief="flat",
        padx=10,
        pady=4,
    )
    sr_reset_btn.pack(side="left", padx=3)

    sr_undo_btn = tk.Button(
        self.sr_btn_row,
        text="Undo Split",
        command=self.sr_undo_split,
        font=("Segoe UI", 9),
        bg="#333333",
        fg="#ffffff",
        relief="flat",
        padx=10,
        pady=4,
    )
    sr_undo_btn.pack(side="left", padx=3)

    asl_load_btn = tk.Button(
        self.sr_btn_row,
        text="Load ASL Script",
        command=self.load_asl_script,
        font=("Segoe UI", 9),
        bg="#333333",
        fg="#ffffff",
        relief="flat",
        padx=8,
        pady=4,
    )
    asl_load_btn.pack(side="right", padx=3)

    lss_load_btn = tk.Button(
        self.sr_btn_row,
        text="Load .lss Splits",
        command=self.load_lss_splits_file,
        font=("Segoe UI", 9, "bold"),
        bg="#333333",
        fg="#ffffff",
        relief="flat",
        padx=8,
        pady=4,
    )
    lss_load_btn.pack(side="right", padx=3)

    self.target_frame = tk.Frame(self.sr_ctrl_panel, bg="#252526")
    self.target_frame.pack(fill="x", pady=3)

    self.gm_options_frame = tk.Frame(self.sr_ctrl_panel, bg="#252526")
    self.gm_options_frame.pack(fill="x", pady=(3, 0))

    tk.Label(
        self.gm_options_frame,
        text="Game Mode Trackers:",
        font=("Segoe UI", 8, "bold"),
        fg="#aaaaaa",
        bg="#252526",
    ).pack(side="left", padx=(0, 5))

    self.gm_show_gums = tk.BooleanVar(value=False)
    self.gm_show_powerups = tk.BooleanVar(value=False)
    self.gm_show_bonus = tk.BooleanVar(value=False)
    self.gm_show_boss = tk.BooleanVar(value=False)
    self.gm_show_errors = tk.BooleanVar(value=False)

    for text, var in [
        ("Gums", self.gm_show_gums),
        ("Powerups", self.gm_show_powerups),
        ("Bonus", self.gm_show_bonus),
        ("Boss", self.gm_show_boss),
        ("Errors", self.gm_show_errors),
    ]:
      chk = tk.Checkbutton(
          self.gm_options_frame,
          text=text,
          variable=var,
          command=self.on_gm_option_changed,
          font=("Segoe UI", 8),
          fg="#d4d4d4",
          bg="#252526",
          selectcolor="#333333",
          activebackground="#252526",
          activeforeground="#ffffff",
      )
      chk.pack(side="left", padx=4)

    self.sr_show_sph = tk.BooleanVar(value=False)
    sph_chk = tk.Checkbutton(
        self.gm_options_frame,
        text="Show SPH",
        variable=self.sr_show_sph,
        command=lambda: [self.save_config(), self.rebuild_sr_splits_ui()],
        font=("Segoe UI", 8, "bold"),
        fg="#55ff55",
        bg="#252526",
        selectcolor="#333333",
        activebackground="#252526",
        activeforeground="#ffffff",
    )
    sph_chk.pack(side="right", padx=4)

    self.sr_topmost_var = tk.BooleanVar(value=False)
    self.topmost_chk = tk.Checkbutton(
        self.target_frame,
        text="Toggle Game Mode",
        variable=self.sr_topmost_var,
        command=self.toggle_always_on_top,
        font=("Segoe UI", 8, "bold"),
        fg="#55ff55",
        bg="#252526",
        selectcolor="#333333",
        activebackground="#252526",
        activeforeground="#ffffff",
    )
    self.topmost_chk.pack(side="left", padx=(0, 10))

    self.font_sub_frame = tk.Frame(self.target_frame, bg="#252526")
    self.font_sub_frame.pack(side="left", padx=5)

    tk.Label(
        self.font_sub_frame,
        text="Timer Font:",
        font=("Segoe UI", 8, "bold"),
        fg="#aaaaaa",
        bg="#252526",
    ).pack(side="left", padx=(5, 3))

    self.timer_font_var = tk.StringVar(value="Consolas")
    self.timer_font_combo = ttk.Combobox(
        self.font_sub_frame,
        textvariable=self.timer_font_var,
        values=["Arial", "Calibri", "Cambria", "Cascadia Mono", "Consolas", "Courier New", "Ebrima", "Fixedsys", "Gadugi", "LED Real", "Lucida Console", "Lucida Sans Unicode", "Microsoft Sans Serif", "Modern", "MS Sans Serif", "MS Serif", "Palatino Linotype", "Roman", "Script", "Segoe Script", "Segoe UI", "Tahoma", "Terminal", "Times New Roman", "Tebuchet MS", "Verdana"],
        width=11,
        state="readonly",
    )
    self.timer_font_combo.pack(side="left", padx=3)
    self.timer_font_combo.bind("<<ComboboxSelected>>", self.update_timer_font)

    self.status_sub_frame = tk.Frame(self.target_frame, bg="#252526")
    self.status_sub_frame.pack(side="right", fill="x")

    self.lss_status_lbl = tk.Label(
        self.status_sub_frame,
        text=f"Splits: {getattr(self, 'loaded_lss_filename', 'Default Generator')}",
        font=("Segoe UI", 8, "italic"),
        fg="#888888",
        bg="#252526",
    )
    self.lss_status_lbl.pack(side="right", padx=5)

    self.asl_lbl = tk.Label(
        self.status_sub_frame,
        text=self.asl_status_text,
        font=("Segoe UI", 8, "italic"),
        fg="#888888",
        bg="#252526",
    )
    self.asl_lbl.pack(side="right", padx=5)

    self.splits_outer = splits_outer = tk.Frame(
        self.speedrun_frame,
        bg="#181818",
        bd=2,
        relief="solid",
        highlightthickness=0,
    )
    splits_outer.pack(padx=15, fill="x", pady=8)

    self.header_row = header_row = tk.Frame(
        self.splits_outer, bg="#222222", padx=8, pady=4
    )
    header_row.pack(fill="x")

    tk.Label(
        header_row,
        text="Split",
        font=("Segoe UI", 9, "bold"),
        fg="#aaaaaa",
        bg="#222222",
        width=12,
        anchor="w",
    ).pack(side="left")
    tk.Label(
        header_row,
        text="Time",
        font=("Segoe UI", 9, "bold"),
        fg="#aaaaaa",
        bg="#222222",
        width=9,
        anchor="e",
    ).pack(side="right")
    tk.Label(
        header_row,
        text="Delta",
        font=("Segoe UI", 9, "bold"),
        fg="#aaaaaa",
        bg="#222222",
        width=7,
        anchor="e",
    ).pack(side="right", padx=6)
    
    self.hdr_sph_lbl = tk.Label(
        header_row,
        text="SPH",
        font=("Segoe UI", 9, "bold"),
        fg="#aaaaaa",
        bg="#222222",
        width=7,
        anchor="e",
    )
    self.hdr_sph_lbl.pack(side="right", padx=4)

    tk.Label(
        header_row,
        text="Segment",
        font=("Segoe UI", 9, "bold"),
        fg="#aaaaaa",
        bg="#222222",
        width=8,
        anchor="e",
    ).pack(side="right")

    self.sr_canvas = tk.Canvas(
        self.splits_outer, bg="#141414", highlightthickness=0, height=217
    )
    self.sr_splits_container = tk.Frame(self.sr_canvas, bg="#141414")

    self.sr_splits_container.bind(
        "<Configure>",
        lambda e: self.sr_canvas.configure(
            scrollregion=self.sr_canvas.bbox("all")
        ),
    )
    self.sr_canvas_window = self.sr_canvas.create_window(
        (0, 0), window=self.sr_splits_container, anchor="nw"
    )
    self.sr_canvas.bind(
        "<Configure>",
        lambda e: self.sr_canvas.itemconfig(
            self.sr_canvas_window, width=e.width
        ),
    )

    self.sr_canvas.pack(side="left", fill="both", expand=True)

    self.sr_timer_panel = tk.Frame(
        self.speedrun_frame, bg="#181818", padx=15, pady=10
    )
    self.sr_timer_panel.pack(padx=15, fill="x", pady=(0, 10))

    sub_left = tk.Frame(self.sr_timer_panel, bg="#181818")
    sub_left.pack(side="left", anchor="sw")

    self.sr_substat_lbl = tk.Label(
        sub_left,
        text="PB: --:--",
        font=("Segoe UI", 9),
        fg="#888888",
        bg="#181818",
        anchor="w",
    )
    self.sr_substat_lbl.pack(anchor="w")

    sub_right = tk.Frame(self.sr_timer_panel, bg="#181818")
    sub_right.pack(side="right", anchor="se")

    self.sr_total_time_lbl = tk.Label(
        sub_right,
        text="00:00:00",
        font=("Consolas", 32),
        fg=self.get_accent_hex(),
        bg="#181818",
        anchor="e",
    )
    self.sr_total_time_lbl.pack(anchor="e")
    self.accent_text_labels.append(self.sr_total_time_lbl)

    self.sr_current_seg_lbl = tk.Label(
        sub_right,
        text="00:00.0",
        font=("Consolas", 18),
        fg=self.get_accent_hex(),
        bg="#181818",
        anchor="e",
    )
    self.sr_current_seg_lbl.pack(anchor="e")
    self.accent_text_labels.append(self.sr_current_seg_lbl)

    self.timer_context_menu = tk.Menu(
        self.root, tearoff=0, bg="#252526", fg="#ffffff", activebackground=self.get_accent_hex()
    )
    self.timer_context_menu.add_command(
        label="Edit Splits", command=self.open_edit_splits_window
    )
    self.timer_context_menu.add_separator()
    self.timer_context_menu.add_command(
        label="Start / Split", command=self.sr_split_action
    )
    self.timer_context_menu.add_command(
        label="Undo Split", command=self.sr_undo_split
    )
    self.timer_context_menu.add_command(
        label="Reset Timer", command=self.sr_reset_timer
    )

    for widget in [
        self.speedrun_frame,
        self.splits_outer,
        self.header_row,
        self.sr_canvas,
        self.sr_splits_container,
        self.sr_timer_panel,
        sub_left,
        sub_right,
        self.sr_total_time_lbl,
        self.sr_current_seg_lbl,
        self.sr_substat_lbl,
    ]:
      widget.bind("<Button-3>", self.show_timer_context_menu)
      widget.bind("<Double-Button-1>", lambda e: self.toggle_game_mode_double_click())

    for child in self.header_row.winfo_children():
      child.bind("<Button-3>", self.show_timer_context_menu)
      child.bind("<Double-Button-1>", lambda e: self.toggle_game_mode_double_click())

    self.sr_generate_splits()

  def setup_error_tracker_tab(self):
    self.decrypted_client_active_ptr = 0
    self.view_angles_offsets = [
        0x16D03D80, 0x16D03EA8, 0x16D0BCB0, 0x16D0D180, 0x16D10C78, 0x16D11808, 0x16D12960, 0x16D13740,
        0x16D142D0, 0x16D14E60, 0x16D159F0, 0x16D16580, 0x16D17110, 0x16D17CA0, 0x16D18CD0, 0x16D37270,
        0x16D30F00, 0x16D31278, 0x16D37020, 0x16D37148, 0x16D038E0, 0x16D08780, 0x16D08D48, 0x16D08E70,
        0x16D090C0, 0x16D11930, 0x16D11A58, 0x16D11B80, 0x16D134F0, 0x16D19988, 0x16D19AB0, 0x16D19BD8,
        0x16D19D00, 0x16D19E28, 0x16D19F50, 0x16D1A078, 0x16D1A1A0, 0x16D1A2C8, 0x16D1A3F0, 0x16D1C0D8,
        0x16D1C578, 0x16D30938, 0x16D30A60, 0x16D30B88, 0x16D30CB0, 0x16D30DD8, 0x16D31028, 0x16D31150,
        0x16D313A0, 0x16D35C78, 0x16D38178, 0x16D38618, 0x16D38AB8, 0x16D38F58, 0x16D393F8, 0x16D39E60,
        0x16D3B330, 0x16D3B7D0, 0x16D0EF90, 0x16D00AA0, 0x16D0D870, 0x16D28D80, 0x16D0DF60, 0x16D00038,
        0x16D0F680, 0x16D0E400, 0x16D29910, 0x16D2A5C8, 0x16D150B0, 0x16D0E528, 0x16D1CFE0, 0x16D22A10,
        0x16D1D230, 0x16D0E2D8
    ]

    self._reset_last_value = -1
    self._reset_consistent_reads = 0
    self._reset_last_delta = 0
    self._reset_last_seconds = float("inf")

    et_main_frame = tk.Frame(self.error_tracker_frame, bg="#141414")
    et_main_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=(10, 5))

    title_lbl = tk.Label(
        et_main_frame,
        text="ERROR MONITOR",
        font=("Death Spirit", 16),
        bg="#141414",
        fg="#00bfff",
    )
    title_lbl.pack(pady=(2, 4))
    self.accent_text_labels.append(title_lbl)

    top_bar = tk.Frame(et_main_frame, bg="#141414")
    top_bar.pack(fill=tk.X, pady=(0, 2))

    self.et_status_lbl = tk.Label(
        top_bar,
        text="Status: Initializing...",
        font=("Arial", 11, "bold"),
        bg="#141414",
        fg="#ffaa00",
    )
    self.et_status_lbl.pack(side=tk.LEFT, padx=5)

    rebind_btn = tk.Button(
        top_bar,
        text="Force Re-attach",
        font=("Arial", 9, "bold"),
        bg="#222222",
        fg="#ffffff",
        activebackground="#333333",
        activeforeground="#ffffff",
        relief=tk.FLAT,
        padx=10,
        pady=4,
        command=self.force_reattach_memory,
    )
    rebind_btn.pack(side=tk.RIGHT, padx=5)

    hint_lbl = tk.Label(
        et_main_frame,
        text="💡 Tip: Click any row to Enable / Disable that individual tracker.",
        font=("Arial", 9, "italic"),
        bg="#141414",
        fg="#888888",
    )
    hint_lbl.pack(anchor=tk.W, pady=(0, 2))

    style = ttk.Style()
    style.theme_use("clam")

    style.map(
        "Treeview",
        background=[("selected", "#222222")],
        foreground=[("selected", "#ffffff")],
    )
    
    style.configure(
        "Treeview",
        background="#222222",
        foreground="#ffffff",
        fieldbackground="#222222",
        borderwidth=0,
        relief="flat",
        rowheight=22,
    )
    
    style.layout("Treeview", [('Treeview.treearea', {'sticky': 'nswe'})])
    style.configure("Treeview", bordercolor="#141414", lightcolor="#141414", darkcolor="#141414")
    
    style.configure(
        "Treeview.Heading",
        background="#111111",
        foreground="#00d2ff",
        relief="flat",
        borderwidth=0,
        padding=(4, 4),
        font=("Segoe UI", 9, "bold"),
    )

    table_center_frame = tk.Frame(et_main_frame, bg="#141414")
    table_center_frame.pack(anchor="center", fill=tk.NONE, expand=False, pady=(2, 0))

    self.et_tree = ttk.Treeview(
        table_center_frame, 
        columns=("active", "name", "current", "max"), 
        show="headings", 
        style="Treeview", 
        height=15
    )

    self.et_tree.configure(takefocus=0)

    self.et_tree.column("active", width=60, anchor="center", stretch=False)
    self.et_tree.column("name", width=240, anchor="w", stretch=False)
    self.et_tree.column("current", width=180, anchor="center", stretch=False)
    self.et_tree.column("max", width=180, anchor="center", stretch=False)

    self.et_tree.heading("active", text="Active")
    self.et_tree.heading("name", text="Address / Metric Name")
    self.et_tree.heading("current", text="Current Value")
    self.et_tree.heading("max", text="Max Value")

    self.et_tree.pack(side=tk.TOP, fill="none", expand=False)
    self.et_tree.bind("<Button-1>", self.on_error_tracker_click)

    saved_enabled_errors = self.config_data.get("enabled_errors", {})

    self.error_addresses_def = [
        {
            "key": "reset_value",
            "name": "Reset Value",
            "offset": "0x176F9358",
            "threshold_offset": "0x176F9340",
            "type": "reset_value",
            "max": 0,
            "enabled": saved_enabled_errors.get("reset_value", False),
        },
        {
            "key": "reset_time",
            "name": "Reset Time",
            "offset": "0x176F9358",
            "threshold_offset": "0x176F9340",
            "type": "reset_time",
            "max": 0,
            "enabled": saved_enabled_errors.get("reset_time", False),
        },
        {
            "key": "gsc_ptr",
            "name": "Child GSC",
            "offset": "0x51A3580",
            "type": "child_gsc",
            "max": 0,
            "enabled": saved_enabled_errors.get("gsc_ptr", False),
        },
        {
            "key": "csc_ptr",
            "name": "Child CSC",
            "offset": "0x51A3680",
            "type": "child_csc",
            "max": 0,
            "enabled": saved_enabled_errors.get("csc_ptr", False),
        },
        {
            "key": "mem_tree",
            "name": "MemTree",
            "offset": "0x50DC280",
            "type": "mem_tree",
            "max": 0,
            "enabled": saved_enabled_errors.get("mem_tree", False),
        },
        {
            "key": "gspawn_count",
            "name": "G-Spawn",
            "offset": "0xA549DF4",
            "type": "gspawn",
            "max": 0,
            "enabled": saved_enabled_errors.get("gspawn_count", False),
        },
        {
            "key": "darkness",
            "name": "Darkness",
            "offset": "0x10B315E4",
            "type": "darkness",
            "max": 0,
            "enabled": saved_enabled_errors.get("darkness", False),
        },
        {
            "key": "frame_time",
            "name": "Frame Time",
            "offset": "0x168ED8A8",
            "type": "frame_time",
            "max": 0,
            "enabled": saved_enabled_errors.get("frame_time", False),
        },
        {
            "key": "view_yaw",
            "name": "ViewAngles",
            "offset": "0x3675210",
            "type": "float",
            "max": 0,
            "enabled": saved_enabled_errors.get("view_yaw", False),
        },
        {
            "key": "overall_velocity",
            "name": "Velocity",
            "offset": "0x3675218",
            "type": "overall_velocity",
            "max": 0,
            "enabled": saved_enabled_errors.get("overall_velocity", False),
        },
    ]

    self.et_item_ids = {}
    for item in self.error_addresses_def:
      status_icon = "☑" if item["enabled"] else "☐"
      item_id = self.et_tree.insert(
          "",
          tk.END,
          values=(
              status_icon,
              item["name"],
              "-",
              "0",
          ),
      )
      self.et_item_ids[item["key"]] = item_id

    threading.Thread(target=self.error_tracker_background_loop, daemon=True).start()

  def on_error_tracker_click(self, event):
    row_id = self.et_tree.identify_row(event.y)

    if row_id:
      target_key = None
      for key, tid in self.et_item_ids.items():
        if tid == row_id:
          target_key = key
          break

      if target_key:
        for item in self.error_addresses_def:
          if item["key"] == target_key:
            item["enabled"] = not item["enabled"]
            break

        is_enabled = any(
            i["key"] == target_key and i["enabled"] for i in self.error_addresses_def
        )
        checkbox_symbol = "☑" if is_enabled else "☐"
        current_vals = self.et_tree.item(row_id, "values")
        if current_vals:
          self.et_tree.item(
              row_id,
              values=(
                  checkbox_symbol,
                  current_vals[1],
                  current_vals[2],
                  current_vals[3],
              ),
          )
        self.save_config()

      try:
        self.et_tree.selection_remove(self.et_tree.selection())
      except Exception:
        pass
      
      return "break"

  def error_tracker_background_loop(self):
    self.et_mem_reader = MemoryReader("blackops3.exe")
    while True:
      try:
        if not self.et_mem_reader.h_process:
          self.decrypted_client_active_ptr = 0
          if not self.et_mem_reader.attach():
            self.et_mem_reader.process_name = "boiii.exe"
            if not self.et_mem_reader.attach():
              self.et_mem_reader.process_name = "blackops3.exe"
              time.sleep(2.0)
              continue

        base_addr = self.et_mem_reader.get_module_base("blackops3.exe")
        if base_addr == 0:
          base_addr = self.et_mem_reader.get_module_base(self.et_mem_reader.process_name)
        if base_addr == 0:
          base_addr = 0x140000000

        level_time_val = self.et_mem_reader.read_int32(base_addr + 0xA5502C0)
        if level_time_val is not None:
          if not hasattr(self, "_et_global_prev_level_time"):
            self._et_global_prev_level_time = level_time_val
          if level_time_val < self._et_global_prev_level_time - 2000:
            self._et_force_yaw_reset = True
            self.decrypted_client_active_ptr = 0
            print("[ErrorTracker] Fast restart detected! Resetting ViewAngles to 0 and re-scanning pointers.")
          self._et_global_prev_level_time = level_time_val

        if getattr(self, "_et_force_yaw_reset", False):
          self.decrypted_client_active_ptr = 0
          self._et_force_yaw_reset = False

        if self.decrypted_client_active_ptr == 0:
          for offset in self.view_angles_offsets:
            ptr_raw = self.et_mem_reader.read_bytes(base_addr + offset, 8)
            if ptr_raw:
              full_addr = struct.unpack("Q", ptr_raw)[0]
              if full_addr != 0:
                candidate_base = full_addr & 0xFFFFFFFFFFFF0000
                yaw_addr = candidate_base + 0x7E4C
                test_val = self.et_mem_reader.read_float(yaw_addr)
                if test_val is not None and not math.isnan(test_val) and abs(test_val) < 15000000:
                  self.decrypted_client_active_ptr = candidate_base
                  break

        parsed_values = {}
        for item in self.error_addresses_def:
          key = item["key"]
          
          if not item["enabled"] and key != "view_yaw":
            if key == "gsc_ptr":
              max_val_str = "0 / 130000"
            elif key == "csc_ptr":
              max_val_str = "0 / 65000"
            elif key == "mem_tree":
              max_val_str = "0 / 130000"
            elif key == "gspawn_count":
              max_val_str = "0 / 1024"
            elif key == "darkness":
              max_val_str = "0 / 4194303"
            else:
              max_val_str = f"{item['max']:,.2f}" if isinstance(item["max"], float) else (f"{item['max']:,}" if isinstance(item["max"], int) else str(item["max"]))
            parsed_values[key] = ("DISABLED", max_val_str)
            continue

          val_str = "-"
          max_str = "-"
          numeric_val = 0
          hex_str = item["offset"]
          offset_val = int(hex_str, 16)
          addr = base_addr + offset_val

          if key == "reset_value":
            r_time = self.et_mem_reader.read_int32(addr)
            thresh_addr = base_addr + int(item["threshold_offset"], 16)
            r_thresh = self.et_mem_reader.read_int32(thresh_addr)
            if r_time is not None and r_thresh is not None:
              dynamic_max = 2147483646 - r_thresh
              remaining_reset = dynamic_max - r_time
              val_str = f"{r_time:,}"
              max_str = f"{remaining_reset:,}"
              numeric_val = r_time
            else:
              val_str = "-"
              max_str = "-"

          elif key == "reset_time":
            r_time = self.et_mem_reader.read_int32(addr)
            if r_time is not None:
              now_t = time.time()
              if self._reset_last_value == -1:
                self._reset_last_value = r_time
                self._reset_last_time = now_t
              else:
                dt = now_t - getattr(self, "_reset_last_time", now_t)
                reset_delta = r_time - self._reset_last_value
                if dt > 0 and reset_delta > 0:
                  self._reset_consistent_reads += 1
                  if self._reset_consistent_reads >= 3:
                    thresh_addr = base_addr + int(item["threshold_offset"], 16)
                    r_thresh = self.et_mem_reader.read_int32(thresh_addr) or 0
                    dynamic_max = 2147483646 - r_thresh
                    remaining = dynamic_max - r_time
                    if reset_delta < 1000000:
                      rate = reset_delta / dt
                      if rate > 0:
                        self._reset_last_seconds = remaining / rate
                        self._reset_consistent_reads = 0
                  self._reset_last_delta = reset_delta
                elif reset_delta < 0:
                  self._reset_consistent_reads = 0
                  self._reset_last_seconds = float("inf")
                
                self._reset_last_value = r_time
                self._reset_last_time = now_t

              rem_secs = self._reset_last_seconds
              if rem_secs < float("inf") and rem_secs > 0:
                hrs = int(rem_secs // 3600)
                mins = int((rem_secs % 3600) // 60)
                secs = int(rem_secs % 60)
                if hrs > 0:
                  val_str = f"{hrs}:{mins:02d}:{secs:02d}"
                elif mins > 0:
                  val_str = f"{mins}:{secs:02d}"
                else:
                  val_str = f"{secs}s"
              else:
                val_str = "Calculating..."
              max_str = "0"
            else:
              val_str = "-"
              max_str = "-"

          elif key == "view_yaw":
            yaw_val = None
            if self.decrypted_client_active_ptr != 0:
              yaw_val = self.et_mem_reader.read_float(self.decrypted_client_active_ptr + 0x7E4C)
            
            if yaw_val is None or math.isnan(yaw_val) or abs(yaw_val) > 15000000:
              self.decrypted_client_active_ptr = 0
              for offset in self.view_angles_offsets:
                ptr_raw = self.et_mem_reader.read_bytes(base_addr + offset, 8)
                if ptr_raw:
                  full_addr = struct.unpack("Q", ptr_raw)[0]
                  if full_addr != 0:
                    candidate_base = full_addr & 0xFFFFFFFFFFFF0000
                    test_val = self.et_mem_reader.read_float(candidate_base + 0x7E4C)
                    if test_val is not None and not math.isnan(test_val) and abs(test_val) < 15000000:
                      self.decrypted_client_active_ptr = candidate_base
                      yaw_val = test_val
                      break

            if yaw_val is not None and not math.isnan(yaw_val) and abs(yaw_val) < 15000000:
              if yaw_val <= -1000000.0:
                val_str = f"Turn Left | {yaw_val:.2f}"
              elif yaw_val >= 1000000.0:
                val_str = f"Turn Right | {yaw_val:.2f}"
              else:
                val_str = f"{yaw_val:.2f}"
              max_str = val_str
            else:
              val_str = "Re-aligning..."
              max_str = "-"

            if not item["enabled"]:
              parsed_values[key] = ("DISABLED", max_str)
              continue

          elif key == "gsc_ptr":
            ptr_bytes = self.et_mem_reader.read_bytes(addr, 8)
            curr_val = 0
            if ptr_bytes:
              struct_base = struct.unpack("Q", ptr_bytes)[0]
              if 0x10000 <= struct_base <= 0x7FFFFFFFFFFF:
                res = self.et_mem_reader.read_int32(struct_base + 0x18)
                if res is not None:
                  curr_val = res
                  numeric_val = res
            if numeric_val > item["max"]:
              item["max"] = numeric_val
            val_str = f"{curr_val}"
            max_str = f"{int(item['max'])} / 130000"

          elif key == "csc_ptr":
            ptr_bytes = self.et_mem_reader.read_bytes(addr, 8)
            curr_val = 0
            if ptr_bytes:
              struct_base = struct.unpack("Q", ptr_bytes)[0]
              if 0x10000 <= struct_base <= 0x7FFFFFFFFFFF:
                res = self.et_mem_reader.read_int32(struct_base + 0x18)
                if res is not None:
                  curr_val = res
                  numeric_val = res
            if numeric_val > item["max"]:
              item["max"] = numeric_val
            val_str = f"{curr_val}"
            max_str = f"{int(item['max'])} / 65000"

          elif key == "mem_tree":
            res = self.et_mem_reader.read_int32(addr)
            if res is not None:
              numeric_val = res
              if numeric_val > item["max"]:
                item["max"] = numeric_val
              val_str = f"{res:,}"
              max_str = f"{int(item['max']):,}"

          elif key == "gspawn_count":
            num_free = 0
            free_list_head = self.et_mem_reader.read_bytes(base_addr + 0xA549DF8, 8)
            curr_free = struct.unpack("Q", free_list_head)[0] if free_list_head else 0
            while curr_free != 0 and num_free < 1024:
              num_free += 1
              next_ptr_bytes = self.et_mem_reader.read_bytes(curr_free + 1200, 8)
              curr_free = struct.unpack("Q", next_ptr_bytes)[0] if next_ptr_bytes else 0

            gspawn_addr_val = self.et_mem_reader.read_int32(addr) or 0
            active_entities = gspawn_addr_val - num_free
            numeric_val = active_entities
            if numeric_val > item["max"]:
              item["max"] = numeric_val
            val_str = f"{active_entities:,}"
            max_str = f"{int(item['max']):,} / 1024"

          elif key == "darkness":
            res = self.et_mem_reader.read_int32(addr)
            if res is not None:
              numeric_val = res
              if numeric_val > item["max"]:
                item["max"] = numeric_val
              val_str = f"{res:,}"
              max_str = f"4194303"

          elif key == "frame_time":
            res = self.et_mem_reader.read_int32(addr)
            if res is not None:
              numeric_val = res
              if numeric_val > item["max"]:
                item["max"] = numeric_val

              remaining_ticks = 2147483647 - res
              days = remaining_ticks // (1000 * 60 * 60 * 24)
              hours = (remaining_ticks % (1000 * 60 * 60 * 24)) // (1000 * 60 * 60)
              minutes = (remaining_ticks % (1000 * 60 * 60)) // (1000 * 60)
              seconds = (remaining_ticks % (1000 * 60)) // 1000

              if days > 0:
                val_str = f"{days}d {hours}h {minutes}m {seconds}s"
              elif hours > 0:
                val_str = f"{hours}h {minutes}m {seconds}s"
              elif minutes > 0:
                val_str = f"{minutes}m {seconds}s"
              else:
                val_str = f"{seconds}s"
              max_str = f"{res:,}"

          elif item["type"] == "overall_velocity":
            vel_bytes = self.et_mem_reader.read_bytes(addr, 12)
            if vel_bytes and len(vel_bytes) == 12:
              vel_x, vel_y, vel_z = struct.unpack("fff", vel_bytes)
              overall_speed = math.sqrt(vel_x**2 + vel_y**2 + vel_z**2)
              numeric_val = overall_speed
              val_str = f"{overall_speed:.2f}"
              max_str = f"{overall_speed:.2f}"

          else:
            if item["type"] == "int32":
              res = self.et_mem_reader.read_int32(addr)
              if res is not None:
                numeric_val = res
                val_str = f"{res:,}"
            elif item["type"] == "float":
              res = self.et_mem_reader.read_float(addr)
              if res is not None:
                numeric_val = res
                val_str = f"{res:.2f}"

            if isinstance(numeric_val, (int, float)) and abs(numeric_val) > abs(item["max"]):
              item["max"] = numeric_val
            max_str = f"{item['max']:,}" if isinstance(item["max"], int) else f"{item['max']:,.2f}"

          parsed_values[key] = (val_str, max_str)

        def update_ui():
          self.et_status_lbl.config(
              text=f"Status: Attached to {self.et_mem_reader.process_name} (PID {self.et_mem_reader.pid})",
              fg="#55ff55"
          )
          for key, (v_str, max_str) in parsed_values.items():
            if key in self.et_item_ids:
              item_id = self.et_item_ids[key]
              current_vals = self.et_tree.item(item_id, "values")
              if current_vals:
                is_enabled = any(i["key"] == key and i["enabled"] for i in self.error_addresses_def)
                checkbox_symbol = "☑" if is_enabled else "☐"
                self.et_tree.item(item_id, values=(checkbox_symbol, current_vals[1], v_str, max_str))

          if hasattr(self, "sr_topmost_var") and self.sr_topmost_var.get() and hasattr(self, "gm_error_value_labels"):
            for key, lbl in self.gm_error_value_labels.items():
              if lbl.winfo_exists() and key in parsed_values:
                v_str, max_str = parsed_values[key]
                err_name = ""
                for item in self.error_addresses_def:
                  if item["key"] == key:
                    err_name = item["name"]
                    break

                if key in ["reset_value", "darkness"]:
                  row_text = f"{err_name:<21} {v_str} / {max_str}"
                elif key == "mem_tree":
                  row_text = f"{err_name:<21} {max_str} / 130000"
                elif key in ["gsc_ptr", "csc_ptr", "gspawn_count"]:
                  row_text = f"{err_name:<21} {max_str}"
                else:
                  row_text = f"{err_name:<21} {v_str}"

                lbl.config(text=row_text)

        self.root.after(0, update_ui)

      except Exception as e:
        print(f"[ErrorTracker] Loop error: {e}")
        try:
          self.root.after(
              0,
              lambda: self.et_status_lbl.config(text="Status: Disconnected / Error", fg="#ff5555")
          )
        except Exception:
          pass
        time.sleep(1.5)

      time.sleep(0.1)

  def force_reattach_memory(self):
    if hasattr(self, "et_mem_reader") and self.et_mem_reader:
      self.et_mem_reader.close()
      self.et_mem_reader.h_process = None
      if hasattr(self, "et_status_lbl"):
        self.et_status_lbl.config(text="Status: Forcing re-attach...", fg="#ffaa00")

  def build_game_mode_trackers_display(self, bg_color):
    if (
        hasattr(self, "gm_trackers_display_frame")
        and self.gm_trackers_display_frame.winfo_exists()
    ):
      self.gm_trackers_display_frame.destroy()

    if not (
        self.gm_show_gums.get()
        or self.gm_show_powerups.get()
        or self.gm_show_bonus.get()
        or self.gm_show_boss.get()
        or self.gm_show_errors.get()
    ):
      return

    self.gm_trackers_display_frame = tk.Frame(
        self.speedrun_frame, bg=bg_color, bd=0, highlightthickness=0
    )
    
    if hasattr(self, "sr_topmost_var") and self.sr_topmost_var.get():
      if hasattr(self, "pack_game_mode_layout"):
        self.pack_game_mode_layout()
      else:
        self.gm_trackers_display_frame.pack(fill="x", padx=10, pady=4)
    else:
      self.gm_trackers_display_frame.pack(fill="x", padx=10, pady=4)

    if not hasattr(self, "_gm_badge_refs"):
      self._gm_badge_refs = []

    def make_badge_handler(name, is_powerup, btn_widget, pil_img):
      def handler():
        if is_powerup:
          self.toggle_powerup(name)
          is_active = self.powerup_states.get(name, False)
        else:
          self.toggle_gum_tracker(name)
          is_active = self.gum_tracker_states.get(name, False)

        new_badge_img = self.create_hud_badge(pil_img, is_active)
        self._gm_badge_refs.append(new_badge_img)
        btn_widget.config(image=new_badge_img)
      return handler

    if self.gm_show_gums.get():
      gums_frame = tk.Frame(
          self.gm_trackers_display_frame,
          bg=bg_color,
          bd=0,
          highlightthickness=0,
      )
      gums_frame.pack(fill="x", pady=2)

      active_gums = [g for g in self.selected_gums if g is not None]
      if not active_gums:
        tk.Label(
            gums_frame,
            text="No pack selected",
            font=("Segoe UI", 8, "italic"),
            fg="#777777",
            bg=bg_color,
            bd=0,
            highlightthickness=0,
        ).pack(side="left")
      else:
        for g_name in active_gums:
          is_active = self.gum_tracker_states.get(g_name, False)
          pil_img = self.gum_loaded_pil_images.get(g_name)
          badge_img = self.create_hud_badge(pil_img, is_active)
          self._gm_badge_refs.append(badge_img)

          btn = tk.Button(
              gums_frame,
              text="" if pil_img else g_name[:4],
              image=badge_img,
              bg=bg_color,
              activebackground=bg_color,
              relief="flat",
              bd=0,
              highlightthickness=0,
              cursor="hand2",
          )
          btn.config(command=make_badge_handler(g_name, False, btn, pil_img))
          btn.pack(side="left", padx=2)

    if self.gm_show_powerups.get():
      pw_outer_frame = tk.Frame(
          self.gm_trackers_display_frame,
          bg=bg_color,
          bd=0,
          highlightthickness=0,
      )
      pw_outer_frame.pack(fill="x", pady=2)

      enabled_powerups = ["Max Ammo", "Insta-Kill", "Double Points", "Nuke"]
      if hasattr(self, "optional_vars"):
        for opt_name, var in self.optional_vars.items():
          if hasattr(var, "get") and var.get():
            enabled_powerups.append(opt_name)

      pw_grid_frame = tk.Frame(
          pw_outer_frame, bg=bg_color, bd=0, highlightthickness=0
      )
      pw_grid_frame.pack(side="left", anchor="w")

      for idx, pw_name in enumerate(enabled_powerups):
        row_idx = idx // 7
        col_idx = idx % 7

        is_active = self.powerup_states.get(pw_name, False)
        pil_img = self.loaded_pil_images.get(pw_name)
        badge_img = self.create_hud_badge(pil_img, is_active)
        self._gm_badge_refs.append(badge_img)

        btn = tk.Button(
            pw_grid_frame,
            text="" if pil_img else pw_name[:4],
            image=badge_img,
            bg=bg_color,
            activebackground=bg_color,
            relief="flat",
            bd=0,
            highlightthickness=0,
            cursor="hand2",
        )
        btn.config(command=make_badge_handler(pw_name, True, btn, pil_img))
        btn.grid(row=row_idx, column=col_idx, padx=2, pady=2, sticky="w")

    if self.gm_show_bonus.get():
      b_frame = tk.Frame(
          self.gm_trackers_display_frame,
          bg=bg_color,
          bd=0,
          highlightthickness=0,
      )
      b_frame.pack(fill="x", pady=2)

      preset_name = (
          self.bonus_preset_combo.get()
          if hasattr(self, "bonus_preset_combo")
          else "None"
      )
      tk.Label(
          b_frame,
          text=f"Bonus ({preset_name}):",
          font=("Segoe UI", 8, "bold"),
          fg="#55ff55",
          bg=bg_color,
          bd=0,
          highlightthickness=0,
      ).pack(side="left", padx=(0, 4))

      if preset_name == "None":
        tk.Label(
            b_frame,
            text="Select preset in Bonus Rounds tab",
            font=("Segoe UI", 8, "italic"),
            fg="#858585",
            bg=bg_color,
            bd=0,
            highlightthickness=0,
        ).pack(side="left")
      else:
        try:
          last_r = (
              int(self.bonus_entry.get()) if hasattr(self, "bonus_entry") else 5
          )
          min_i = (
              int(self.bonus_min_entry.get())
              if hasattr(self, "bonus_min_entry")
              else 4
          )
          max_i = (
              int(self.bonus_max_entry.get())
              if hasattr(self, "bonus_max_entry")
              else 5
          )
          b_next_min = last_r + min_i
          b_next_max = last_r + max_i

          for r_val in range(b_next_min, b_next_max + 1):
            btn = tk.Button(
                b_frame,
                text=f"{r_val}",
                command=lambda r=r_val: self.select_bonus_round(r),
                font=("Segoe UI", 8, "bold"),
                bg=self.get_accent_hex(),
                fg="#ffffff",
                relief="flat",
                bd=0,
                highlightthickness=0,
                padx=5,
                pady=1,
                cursor="hand2",
            )
            btn.pack(side="left", padx=2)
        except Exception:
          tk.Label(
              b_frame,
              text="--",
              font=("Segoe UI", 8),
              fg="#aaaaaa",
              bg=bg_color,
              bd=0,
              highlightthickness=0,
          ).pack(side="left")

      if preset_name == "Excavator (Moon)":
        loc_frame = tk.Frame(
            self.gm_trackers_display_frame,
            bg=bg_color,
            bd=0,
            highlightthickness=0,
        )
        loc_frame.pack(fill="x", pady=(0, 2))

        tk.Label(
            loc_frame,
            text="Location:",
            font=("Segoe UI", 8, "bold"),
            fg="#aaaaaa",
            bg=bg_color,
            bd=0,
            highlightthickness=0,
        ).pack(side="left", padx=(12, 4))

        for loc in ["Tunnel 6", "Tunnel 11", "Biodome"]:
          is_active_loc = (
              hasattr(self, "selected_excavator_location")
              and self.selected_excavator_location == loc
          )
          loc_bg = self.get_accent_hex() if is_active_loc else "#333333"
          loc_btn = tk.Button(
              loc_frame,
              text=loc,
              command=lambda l=loc: [
                  self.set_excavator_location(l),
                  self.build_game_mode_trackers_display(bg_color),
              ],
              font=("Segoe UI", 7, "bold"),
              bg=loc_bg,
              fg="#ffffff",
              relief="flat",
              bd=0,
              highlightthickness=0,
              padx=4,
              pady=1,
              cursor="hand2",
          )
          loc_btn.pack(side="left", padx=2)

    if self.gm_show_boss.get():
      br_frame = tk.Frame(
          self.gm_trackers_display_frame,
          bg=bg_color,
          bd=0,
          highlightthickness=0,
      )
      br_frame.pack(fill="x", pady=2)

      boss_preset = (
          self.boss_preset_combo.get()
          if hasattr(self, "boss_preset_combo")
          else "None"
      )
      tk.Label(
          br_frame,
          text=f"Boss ({boss_preset}):",
          font=("Segoe UI", 8, "bold"),
          fg="#ff5555",
          bg=bg_color,
          bd=0,
          highlightthickness=0,
      ).pack(side="left", padx=(0, 4))

      if boss_preset == "None":
        tk.Label(
            br_frame,
            text="Select preset in Boss Rounds tab",
            font=("Segoe UI", 8, "italic"),
            fg="#858585",
            bg=bg_color,
            bd=0,
            highlightthickness=0,
        ).pack(side="left")
      else:
        try:
          last_br = (
              int(self.boss_entry.get()) if hasattr(self, "boss_entry") else 8
          )
          min_bi = (
              int(self.boss_min_entry.get())
              if hasattr(self, "boss_min_entry")
              else 4
          )
          max_bi = (
              int(self.boss_max_entry.get())
              if hasattr(self, "boss_max_entry")
              else 5
          )
          br_next_min = last_br + min_bi
          br_next_max = last_br + max_bi

          for r_val in range(br_next_min, br_next_max + 1):
            btn = tk.Button(
                br_frame,
                text=f"{r_val}",
                command=lambda r=r_val: self.select_boss_round(r),
                font=("Segoe UI", 8, "bold"),
                bg=self.get_accent_hex(),
                fg="#ffffff",
                relief="flat",
                bd=0,
                highlightthickness=0,
                padx=5,
                pady=1,
                cursor="hand2",
            )
            btn.pack(side="left", padx=2)
        except Exception:
          tk.Label(
              br_frame,
              text="--",
              font=("Segoe UI", 8),
              fg="#aaaaaa",
              bg=bg_color,
              bd=0,
              highlightthickness=0,
          ).pack(side="left")

    if self.gm_show_errors.get() and hasattr(self, "error_addresses_def"):
      err_frame = tk.Frame(
          self.gm_trackers_display_frame,
          bg=bg_color,
          bd=0,
          highlightthickness=0,
      )
      err_frame.pack(fill="x", pady=2)

      tk.Label(
          err_frame,
          text="Error Monitors:",
          font=("Consolas", 8, "bold"),
          fg="#00bfff",
          bg=bg_color,
          bd=0,
          highlightthickness=0,
      ).pack(side="top", anchor="w", padx=(0, 4))

      self.gm_error_value_labels = {}
      enabled_errors = [item for item in self.error_addresses_def if item.get("enabled")]
      if not enabled_errors:
        tk.Label(
            err_frame,
            text="No error monitors enabled",
            font=("Consolas", 8, "italic"),
            fg="#858585",
            bg=bg_color,
            bd=0,
            highlightthickness=0,
        ).pack(side="top", anchor="w")
      else:
        for err in enabled_errors:
          item_id = self.et_item_ids.get(err["key"]) if hasattr(self, "et_item_ids") else None
          curr_val = "-"
          max_val = "0"
          if item_id and hasattr(self, "et_tree"):
            vals = self.et_tree.item(item_id, "values")
            if vals and len(vals) >= 4:
              curr_val = vals[2]
              max_val = vals[3]

          name_upper = err["name"].upper()
          key = err["key"]

          if key in ["reset_value", "darkness"]:
            row_text = f"{name_upper:<21} {curr_val} / {max_val}"
          elif key == "mem_tree":
            row_text = f"{name_upper:<21} {max_val} / 130000"
          elif key in ["gsc_ptr", "csc_ptr", "gspawn_count"]:
            row_text = f"{name_upper:<21} {max_val}"
          else:
            row_text = f"{name_upper:<21} {curr_val}"

          val_lbl = tk.Label(
              err_frame,
              text=row_text,
              font=("Consolas", 9, "bold"),
              fg="#ffffff",
              bg=bg_color,
              bd=0,
              highlightthickness=0,
              anchor="w",
              padx=12
          )
          val_lbl.pack(fill="x", anchor="w")
          self.gm_error_value_labels[err["key"]] = val_lbl

    if hasattr(self, "sr_topmost_var") and self.sr_topmost_var.get() and hasattr(self, "pack_game_mode_layout"):
      self.pack_game_mode_layout()

  def on_gm_option_changed(self):
    self.save_config()
    if hasattr(self, "sr_topmost_var") and self.sr_topmost_var.get():
      self.build_game_mode_trackers_display("#000002")

  def update_timer_font(self, event=None):
    font_name = self.timer_font_var.get()
    if hasattr(self, "sr_total_time_lbl") and self.sr_total_time_lbl.winfo_exists():
      self.sr_total_time_lbl.config(font=(font_name, 32))
    if hasattr(self, "sr_current_seg_lbl") and self.sr_current_seg_lbl.winfo_exists():
      self.sr_current_seg_lbl.config(font=(font_name, 18))
    self.rebuild_sr_splits_ui()
    self.save_config()

  def exit_game_mode_shortcut(self):
    if self.sr_topmost_var.get():
      self.sr_topmost_var.set(False)
      self.toggle_always_on_top()

  def toggle_game_mode_double_click(self):
    current = self.sr_topmost_var.get()
    self.sr_topmost_var.set(not current)
    self.toggle_always_on_top()

  def show_timer_context_menu(self, event):
    self.timer_context_menu.tk_popup(event.x_root, event.y_root)

  def _start_move(self, event):
    if self.sr_topmost_var.get():
      self._drag_x = event.x_root
      self._drag_y = event.y_root

  def _do_move(self, event):
    if self.sr_topmost_var.get():
      x = self.root.winfo_x() + (event.x_root - self._drag_x)
      y = self.root.winfo_y() + (event.y_root - self._drag_y)
      self.root.geometry(f"+{x}+{y}")
      self._drag_x = event.x_root
      self._drag_y = event.y_root

  def update_drag_bar_visibility(self, is_paused):
    if not hasattr(self, "gm_drag_bar") or not self.gm_drag_bar.winfo_exists():
      return

    is_currently_mapped = self.gm_drag_bar.winfo_ismapped()

    if is_paused and not is_currently_mapped:
      ctrl_panel = getattr(self, "sr_ctrl_panel", None)
      if ctrl_panel and ctrl_panel.winfo_exists():
        self.gm_drag_bar.pack(fill="x", side="top", before=ctrl_panel, pady=(0, 2))
      else:
        self.gm_drag_bar.pack(fill="x", side="top", pady=(0, 2))
    elif not is_paused and is_currently_mapped:
      self.gm_drag_bar.pack_forget()

  def toggle_always_on_top(self):
    is_topmost = self.sr_topmost_var.get()
    self.root.attributes("-topmost", is_topmost)

    TRANS_COLOR = "#000002"

    if is_topmost:
      for idx, frame in enumerate(self.pages):
        if frame == self.speedrun_frame:
          frame.pack(fill="both", expand=True)
        else:
          frame.pack_forget()

      self.tab_bar.pack_forget()

      for widget_name in [
          "sr_title_lbl",
          "credit_lbl",
          "sr_btn_row",
          "font_sub_frame",
          "gm_options_frame",
          "status_sub_frame",
      ]:
        if hasattr(self, widget_name):
          w = getattr(self, widget_name)
          if w and w.winfo_exists():
            w.pack_forget()

      self.root.overrideredirect(True)

      overhead_height = 220 + 32 + 22 + 30

      if self.gm_show_gums.get():
        overhead_height += 40

      if self.gm_show_powerups.get():
        enabled_powerups_count = 4
        if hasattr(self, "optional_vars"):
          for opt_name, var in self.optional_vars.items():
            if hasattr(var, "get") and var.get():
              enabled_powerups_count += 1
        num_rows = math.ceil(enabled_powerups_count / 7.0)
        overhead_height += (num_rows * 42) + 15

      if self.gm_show_bonus.get():
        overhead_height += 35
        if (
            hasattr(self, "bonus_preset_combo")
            and self.bonus_preset_combo.get() == "Excavator (Moon)"
        ):
          overhead_height += 28

      if self.gm_show_boss.get():
        overhead_height += 35

      if self.gm_show_errors.get() and hasattr(self, "error_addresses_def"):
        enabled_errors = [item for item in self.error_addresses_def if item.get("enabled")]
        if enabled_errors:
          overhead_height += (len(enabled_errors) * 20) + 30

      screen_w = self.root.winfo_screenwidth()
      screen_h = self.root.winfo_screenheight()
      max_allowed_height = screen_h - 80

      num_visible = min(7, len(self.splits_list))
      base_height = overhead_height + (num_visible * 31)

      while base_height > max_allowed_height and num_visible > 2:
        num_visible -= 1
        base_height = overhead_height + (num_visible * 31)

      base_height = min(base_height, max_allowed_height)
      overlay_width = 450 if screen_w >= 1920 else 400
      self.root.geometry(f"{overlay_width}x{base_height}")

      try:
        self.root.wm_attributes("-transparentcolor", TRANS_COLOR)
      except Exception:
        pass
      self.root.config(bg=TRANS_COLOR)
      self.content_container.config(bg=TRANS_COLOR)
      self.speedrun_frame.config(bg=TRANS_COLOR)

      if hasattr(self, "gm_drag_bar") and self.gm_drag_bar.winfo_exists():
        self.gm_drag_bar.destroy()

      self.gm_drag_bar = tk.Frame(self.speedrun_frame, bg=self.get_accent_hex(), height=22)
      self.gm_drag_bar.pack_propagate(False)

      drag_lbl = tk.Label(
          self.gm_drag_bar,
          text="☰ DRAG TO MOVE | DO NOT COVER IDENTIFIER ☰",
          font=("Segoe UI", 7, "bold"),
          fg="#ffffff",
          bg=self.get_accent_hex(),
      )
      drag_lbl.pack(expand=True)

      for w_drag in [self.gm_drag_bar, drag_lbl]:
        w_drag.bind("<Button-1>", self._start_move)
        w_drag.bind("<B1-Motion>", self._do_move)

      if hasattr(self, "sr_ctrl_panel") and self.sr_ctrl_panel.winfo_exists():
        self.sr_ctrl_panel.config(bg=TRANS_COLOR, highlightthickness=0, bd=0, relief="flat", padx=0, pady=0)

      if hasattr(self, "splits_outer"):
        self.splits_outer.config(bg=TRANS_COLOR, bd=0, relief="flat", highlightthickness=0)

      if hasattr(self, "header_row"):
        self.header_row.config(bg=TRANS_COLOR)
        for child in self.header_row.winfo_children():
          child.config(bg=TRANS_COLOR)

      if hasattr(self, "sr_canvas"):
        self.sr_canvas.config(bg=TRANS_COLOR, highlightthickness=0)
      if hasattr(self, "sr_splits_container"):
        self.sr_splits_container.config(bg=TRANS_COLOR)

      self.build_game_mode_trackers_display(TRANS_COLOR)
      self.rebuild_sr_splits_ui()

      if hasattr(self, "gm_trackers_display_frame") and self.gm_trackers_display_frame.winfo_exists():
        self.gm_trackers_display_frame.config(bg=TRANS_COLOR)
        for child in self.gm_trackers_display_frame.winfo_children():
          if not isinstance(child, tk.Button):
            child.config(bg=TRANS_COLOR)
          for sub in child.winfo_children():
            try:
              if not isinstance(sub, tk.Button):
                sub.config(bg=TRANS_COLOR)
            except Exception:
              pass

      if hasattr(self, "sr_timer_panel"):
        self.sr_timer_panel.config(bg=TRANS_COLOR)
        for child in self.sr_timer_panel.winfo_children():
          child.config(bg=TRANS_COLOR)
          for sub in child.winfo_children():
            sub.config(bg=TRANS_COLOR)

      if hasattr(self, "sr_splits_container"):
        for row in self.sr_splits_container.winfo_children():
          row.config(bg=TRANS_COLOR)
          for item in row.winfo_children():
            try:
              item.config(bg=TRANS_COLOR)
            except Exception:
              pass

      self.pack_game_mode_layout()

    else:
      try:
        self.root.wm_attributes("-transparentcolor", "")
      except Exception:
        pass

      if hasattr(self, "gm_drag_bar") and self.gm_drag_bar.winfo_exists():
        self.gm_drag_bar.destroy()

      if hasattr(self, "gm_trackers_display_frame") and self.gm_trackers_display_frame.winfo_exists():
        self.gm_trackers_display_frame.destroy()

      self.root.overrideredirect(False)
      self.root.geometry("800x800")

      self.root.config(bg="#1e1e1e")
      self.content_container.config(bg="#1e1e1e")
      self.speedrun_frame.config(bg="#1e1e1e")

      if hasattr(self, "sr_ctrl_panel") and self.sr_ctrl_panel.winfo_exists():
        self.sr_ctrl_panel.config(bg="#252526", highlightthickness=0, bd=0, relief="flat")
        for child in self.sr_ctrl_panel.winfo_children():
          try:
            child.config(bg="#252526", activebackground="#252526")
            if isinstance(child, tk.Checkbutton):
              child.config(selectcolor="#252526")
          except Exception:
            pass
      if hasattr(self, "target_frame") and self.target_frame.winfo_exists():
        self.target_frame.config(bg="#252526")
      if hasattr(self, "topmost_chk") and self.topmost_chk.winfo_exists():
        self.topmost_chk.config(bg="#252526", activebackground="#252526", selectcolor="#252526")

      if hasattr(self, "sr_btn_row") and self.sr_btn_row.winfo_exists():
        self.sr_btn_row.pack(fill="x", pady=(0, 5), before=self.target_frame if hasattr(self, "target_frame") else None)
      if hasattr(self, "font_sub_frame") and self.font_sub_frame.winfo_exists():
        self.font_sub_frame.pack(side="left", padx=5)
      if hasattr(self, "gm_options_frame") and self.gm_options_frame.winfo_exists():
        self.gm_options_frame.pack(fill="x", pady=(3, 0), before=self.target_frame if hasattr(self, "target_frame") else None)
      if hasattr(self, "status_sub_frame") and self.status_sub_frame.winfo_exists():
        self.status_sub_frame.pack(side="right", fill="x")

      if hasattr(self, "sr_start_btn") and self.sr_start_btn.winfo_exists():
        self.sr_start_btn.config(bg=self.get_accent_hex(), fg="#ffffff")

      if hasattr(self, "splits_outer"):
        self.splits_outer.config(bg="#181818", bd=2, relief="solid")
      if hasattr(self, "header_row"):
        self.header_row.config(bg="#222222")
        for child in self.header_row.winfo_children():
          child.config(bg="#222222")

      if hasattr(self, "sr_canvas"):
        self.sr_canvas.config(bg="#141414")
      if hasattr(self, "sr_splits_container"):
        self.sr_splits_container.config(bg="#141414")
      if hasattr(self, "sr_timer_panel"):
        self.sr_timer_panel.config(bg="#181818")
        for child in self.sr_timer_panel.winfo_children():
          child.config(bg="#181818")
          for sub in child.winfo_children():
            sub.config(bg="#181818")
        
        if hasattr(self, "sr_substat_lbl") and self.sr_substat_lbl.winfo_exists():
          self.sr_substat_lbl.config(bg="#181818")
        if hasattr(self, "sr_total_time_lbl") and self.sr_total_time_lbl.winfo_exists():
          self.sr_total_time_lbl.config(bg="#181818", fg=self.get_accent_hex())
        if hasattr(self, "sr_current_seg_lbl") and self.sr_current_seg_lbl.winfo_exists():
          self.sr_current_seg_lbl.config(bg="#181818", fg=self.get_accent_hex())

      self.tab_bar.pack_forget()
      self.content_container.pack_forget()
      if hasattr(self, "credit_lbl") and self.credit_lbl.winfo_exists():
        self.credit_lbl.pack_forget()

      self.tab_bar.pack(fill="x", padx=10, pady=(10, 0))
      self.content_container.pack(fill="both", expand=True, padx=10, pady=10)
      if hasattr(self, "credit_lbl") and self.credit_lbl.winfo_exists():
        self.credit_lbl.pack(side="bottom", fill="x", pady=(0, 4))

      self.show_page(5)

      for w in [
          getattr(self, "sr_title_lbl", None),
          getattr(self, "sr_ctrl_panel", None),
          getattr(self, "splits_outer", None),
          getattr(self, "sr_timer_panel", None),
      ]:
        if w and hasattr(w, "winfo_exists") and w.winfo_exists():
          w.pack_forget()

      if hasattr(self, "sr_title_lbl") and self.sr_title_lbl.winfo_exists():
        self.sr_title_lbl.pack(pady=(10, 5))
      if hasattr(self, "sr_ctrl_panel") and self.sr_ctrl_panel.winfo_exists():
        self.sr_ctrl_panel.pack(padx=15, fill="x", pady=5)
      if hasattr(self, "splits_outer") and self.splits_outer.winfo_exists():
        self.splits_outer.pack(padx=15, fill="both", expand=True, pady=8)
      if hasattr(self, "sr_timer_panel") and self.sr_timer_panel.winfo_exists():
        self.sr_timer_panel.pack(padx=15, fill="x", pady=(0, 10))

      self.rebuild_sr_splits_ui()

  def pack_game_mode_layout(self):
    if not hasattr(self, "sr_topmost_var") or not self.sr_topmost_var.get():
      return

    for w in [
        getattr(self, "gm_drag_bar", None),
        getattr(self, "sr_ctrl_panel", None),
        getattr(self, "splits_outer", None),
        getattr(self, "gm_trackers_display_frame", None),
        getattr(self, "sr_timer_panel", None),
    ]:
      if w and hasattr(w, "winfo_exists") and w.winfo_exists():
        w.pack_forget()

    if hasattr(self, "gm_drag_bar") and self.gm_drag_bar.winfo_exists():
      self.gm_drag_bar.pack(fill="x", side="top", pady=(0, 2))

    if hasattr(self, "sr_ctrl_panel") and self.sr_ctrl_panel.winfo_exists():
      self.sr_ctrl_panel.pack(fill="x", side="top", pady=(0, 2), padx=0)

    if hasattr(self, "splits_outer") and self.splits_outer.winfo_exists():
      self.splits_outer.pack(fill="both", expand=False, side="top", pady=(0, 4))

    if hasattr(self, "sr_timer_panel") and self.sr_timer_panel.winfo_exists():
      self.sr_timer_panel.pack(fill="x", side="top", pady=(0, 4))

    if hasattr(self, "gm_trackers_display_frame") and self.gm_trackers_display_frame.winfo_exists():
      self.gm_trackers_display_frame.pack(fill="x", side="top", pady=(0, 0))

  def update_sr_substat_display(self):
    if not self.splits_list or self.current_split_index >= len(self.splits_list):
      if hasattr(self, "sr_substat_lbl") and self.sr_substat_lbl.winfo_exists():
        self.sr_substat_lbl.config(text="PB: Finished")
      return

    current_split = self.splits_list[self.current_split_index]
    pb_total = current_split.get("pb_total", 0.0)
    
    prev_pb_total = (
        self.splits_list[self.current_split_index - 1]["pb_total"]
        if self.current_split_index > 0
        else 0.0
    )
    pb_seg = pb_total - prev_pb_total

    substat_str = f"Segment time: {self.format_time_short(pb_seg)}"
    if hasattr(self, "sr_substat_lbl") and self.sr_substat_lbl.winfo_exists():
      self.sr_substat_lbl.config(text=substat_str)

  def load_lss_splits_file(self, file_path=None):
    if not file_path:
      file_path = filedialog.askopenfilename(
          title="Select Splits File",
          filetypes=[
              ("Splits Files", "*.lss;*.json"),
              ("LiveSplit Files", "*.lss"),
              ("JSON Splits", "*.json"),
              ("All Files", "*.*"),
          ],
      )

    if file_path:
      try:
        if file_path.endswith(".json"):
          with open(file_path, "r", encoding="utf-8") as f:
            data = json.load(f)
          parsed_splits = []
          for item in data:
            parsed_splits.append({
                "name": item.get("name", "Split"),
                "completed": False,
                "total_time": None,
                "segment_time": None,
                "delta_str": "",
                "pb_total": float(item.get("pb_total", 0.0)),
            })
          if parsed_splits:
            self.splits_list = parsed_splits
            self.current_split_index = 0
            self.loaded_lss_path = file_path
            self.loaded_lss_filename = os.path.basename(file_path)
            self.lss_status_lbl.config(
                text=f"Splits: {self.loaded_lss_filename}", fg="#55ff55"
            )
            self.update_sr_substat_display()
            self.rebuild_sr_splits_ui()
            self.save_config()
          return

        tree = ET.parse(file_path)
        root = tree.getroot()
        parsed_splits = []

        for segment in root.findall(".//Segment"):
          name_elem = segment.find("Name")
          segment_name = (
              name_elem.text
              if name_elem is not None and name_elem.text
              else "Unknown"
          )

          pb_seconds = 0.0
          for split_time in segment.findall(".//SplitTime"):
            if split_time.get("name") == "Personal Best":
              gt_elem = split_time.find("GameTime")
              if gt_elem is not None and gt_elem.text:
                pb_seconds = self.parse_duration_to_seconds(gt_elem.text)

          parsed_splits.append({
              "name": segment_name.strip(),
              "completed": False,
              "total_time": None,
              "segment_time": None,
              "delta_str": "",
              "pb_total": pb_seconds,
          })

        if parsed_splits:
          self.splits_list = parsed_splits
          self.current_split_index = 0
          self.loaded_lss_path = file_path
          self.loaded_lss_filename = os.path.basename(file_path)
          self.lss_status_lbl.config(
              text=f"Splits: {self.loaded_lss_filename}", fg="#55ff55"
          )
          self.update_sr_substat_display()
          self.rebuild_sr_splits_ui()
          self.save_config()
        else:
          messagebox.showwarning(
              "Warning",
              "No segments were found in the selected splits file.",
          )
      except Exception as e:
        messagebox.showerror(
            "Load Failed", f"Could not parse splits file: {e}"
        )

  def open_edit_splits_window(self):
    edit_win = tk.Toplevel(self.root)
    edit_win.title("Edit Splits (Segment Times)")
    edit_win.geometry("450x550")

    self.root.update_idletasks()
    main_x = self.root.winfo_rootx()
    main_y = self.root.winfo_rooty()
    main_w = self.root.winfo_width()
    main_h = self.root.winfo_height()

    popup_w, popup_h = 450, 550
    pos_x = main_x + (main_w - popup_w) // 2
    pos_y = main_y + (main_h - popup_h) // 2
    edit_win.geometry(f"{popup_w}x{popup_h}+{pos_x}+{pos_y}")

    edit_win.configure(bg="#1e1e1e")
    edit_win.transient(self.root)
    edit_win.grab_set()

    tk.Label(
        edit_win,
        text="Edit Split Names & Segment Times",
        font=("Segoe UI", 11, "bold"),
        fg="#ff5555",
        bg="#1e1e1e",
    ).pack(pady=(10, 5))

    container = tk.Frame(edit_win, bg="#1e1e1e")
    container.pack(fill="both", expand=True, padx=10, pady=5)

    canvas = tk.Canvas(container, bg="#1e1e1e", highlightthickness=0)
    scrollbar = ttk.Scrollbar(container, orient="vertical", command=canvas.yview)
    scroll_frame = tk.Frame(canvas, bg="#1e1e1e")

    scroll_frame.bind(
        "<Configure>",
        lambda e: canvas.configure(scrollregion=canvas.bbox("all")),
    )
    window_id = canvas.create_window((0, 0), window=scroll_frame, anchor="nw")
    canvas.bind(
        "<Configure>",
        lambda e: canvas.itemconfig(window_id, width=e.width),
    )
    canvas.configure(yscrollcommand=scrollbar.set)

    canvas.pack(side="left", fill="both", expand=True)
    scrollbar.pack(side="right", fill="y")

    def _on_mousewheel(event):
      try:
        canvas.yview_scroll(int(-1 * (event.delta / 120)), "units")
      except Exception:
        pass

    edit_win.bind_all("<MouseWheel>", _on_mousewheel)

    row_entries = []

    def populate_rows():
      for w in scroll_frame.winfo_children():
        w.destroy()
      row_entries.clear()

      hdr = tk.Frame(scroll_frame, bg="#252526", padx=5, pady=4)
      hdr.pack(fill="x", pady=2)
      tk.Label(
          hdr,
          text="Split Name",
          font=("Segoe UI", 9, "bold"),
          fg="#d4d4d4",
          bg="#252526",
          width=22,
          anchor="w",
      ).pack(side="left")
      tk.Label(
          hdr,
          text="Segment (sec)",
          font=("Segoe UI", 9, "bold"),
          fg="#d4d4d4",
          bg="#252526",
          width=15,
          anchor="w",
      ).pack(side="left", padx=5)

      prev_cumulative = 0.0
      for i, split in enumerate(self.splits_list):
        seg_time = split["pb_total"] - prev_cumulative
        prev_cumulative = split["pb_total"]

        r_frame = tk.Frame(scroll_frame, bg="#2d2d2d", padx=5, pady=4)
        r_frame.pack(fill="x", pady=2)

        name_entry = tk.Entry(
            r_frame,
            font=("Segoe UI", 9),
            width=22,
            bg="#333333",
            fg="#ffffff",
            insertbackground="white",
        )
        name_entry.insert(0, split["name"])
        name_entry.pack(side="left")

        time_entry = tk.Entry(
            r_frame,
            font=("Segoe UI", 9),
            width=15,
            bg="#333333",
            fg="#ffffff",
            insertbackground="white",
        )
        time_entry.insert(0, f"{seg_time:.1f}")
        time_entry.pack(side="left", padx=5)

        del_btn = tk.Button(
            r_frame,
            text="✕",
            command=lambda idx=i: remove_split(idx),
            font=("Segoe UI", 8, "bold"),
            bg="#ff5555",
            fg="#ffffff",
            relief="flat",
            width=2,
        )
        del_btn.pack(side="right", padx=2)

        row_entries.append((name_entry, time_entry))

    def remove_split(idx):
      if len(self.splits_list) > 1:
        self.splits_list.pop(idx)
        populate_rows()
      else:
        messagebox.showwarning(
            "Warning", "You must keep at least one split.", parent=edit_win
        )

    def add_new_split():
      self.splits_list.append({
          "name": f"Split {len(self.splits_list) + 1}",
          "completed": False,
          "total_time": None,
          "segment_time": None,
          "delta_str": "",
          "pb_total": 0.0,
      })
      populate_rows()

    populate_rows()

    btn_frame = tk.Frame(edit_win, bg="#1e1e1e", pady=10)
    btn_frame.pack(fill="x")

    tk.Button(
        btn_frame,
        text="Add Split",
        command=add_new_split,
        font=("Segoe UI", 9, "bold"),
        bg="#333333",
        fg="#ffffff",
        relief="flat",
        padx=10,
        pady=5,
    ).pack(side="left", padx=15)

    def save_edits():
      try:
        new_splits = []
        running_cumulative = 0.0
        for idx, (n_ent, t_ent) in enumerate(row_entries):
          s_name = n_ent.get().strip() or f"Split {idx+1}"
          s_seg = float(t_ent.get().strip() or "0.0")
          running_cumulative += s_seg

          new_splits.append({
              "name": s_name,
              "completed": False,
              "total_time": None,
              "segment_time": None,
              "delta_str": "",
              "pb_total": running_cumulative,
          })
        if new_splits:
          self.splits_list = new_splits
          self.current_split_index = min(
              self.current_split_index, len(self.splits_list) - 1
          )
          self.rebuild_sr_splits_ui()
          edit_win.unbind_all("<MouseWheel>")
          if hasattr(self, "calc_canvas") and self.pages[0].winfo_ismapped():
            self.calc_canvas.bind_all("<MouseWheel>", self._on_calc_mousewheel)
          edit_win.destroy()
      except ValueError:
        messagebox.showerror(
            "Invalid Input",
            "Please ensure all segment times are valid numbers (seconds).",
            parent=edit_win,
        )

    tk.Button(
        btn_frame,
        text="Save & Apply",
        command=save_edits,
        font=("Segoe UI", 9, "bold"),
        bg=self.get_accent_hex(),
        fg="#ffffff",
        relief="flat",
        padx=12,
        pady=5,
    ).pack(side="right", padx=15)

    def on_closing():
      edit_win.unbind_all("<MouseWheel>")
      if hasattr(self, "calc_canvas") and self.pages[0].winfo_ismapped():
        self.calc_canvas.bind_all("<MouseWheel>", self._on_calc_mousewheel)
      edit_win.destroy()

    edit_win.protocol("WM_DELETE_WINDOW", on_closing)

  def parse_duration_to_seconds(self, dur_str):
    try:
      parts = dur_str.split(":")
      if len(parts) == 3:
        h = float(parts[0])
        m = float(parts[1])
        s = float(parts[2])
        return h * 3600.0 + m * 60.0 + s
      elif len(parts) == 2:
        m = float(parts[0])
        s = float(parts[1])
        return m * 60.0 + s
      else:
        return float(dur_str)
    except Exception:
      return 0.0

  def load_asl_script(self, file_path=None):
    if not file_path:
      file_path = filedialog.askopenfilename(
          title="Select LiveSplit ASL Script",
          filetypes=[("Auto Splitter Script", "*.asl"), ("All Files", "*.*")],
      )
    
    if file_path:
      try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
          content = f.read()

        self.asl_script_loaded = True
        self.loaded_asl_path = file_path
        filename = os.path.basename(file_path)
        self.asl_status_text = f"ASL Active: {filename}"
        self.asl_lbl.config(text=self.asl_status_text, fg="#55ff55")

        threading.Thread(
            target=self.run_asl_memory_listener, daemon=True
        ).start()
        self.save_config()
      except Exception as e:
        messagebox.showerror(
            "Load Failed", f"Could not parse script file: {e}"
        )

  def run_asl_memory_listener(self):
    OFFSETS_CONFIG = {
        "blackops3.exe": {
            "game": "bo3",
            "round": 0xA55BDEC,
            "level_time": 0xA5502C0,
            "is_paused": 0x347EE08,
            "map": 0x179DF840,
        },
        "boiii.exe": {
            "game": "bo3",
            "round": 0xA55BDEC,
            "level_time": 0xA5502C0,
            "is_paused": 0x347EE08,
            "map": 0x179DF840,
        },
        "blackops3_unrankeddedicatedserver.exe": {
            "game": "bo3",
            "round": 0xA55BDEC,
            "level_time": 0xA5502C0,
            "is_paused": 0x347EE08,
            "map": 0x179DF840,
        },
        "t7x.exe": {
            "game": "bo3",
            "round": 0xA55BDEC,
            "level_time": 0xA5502C0,
            "is_paused": 0x347EE08,
            "map": 0x179DF840,
        },
        "blackops.exe": {
            "game": "bo1",
            "ticks": 0x1679870,
            "round_change": 0x165695D,
            "map": 0x2162950,
            "x": 0x1679710,
        },
        "bgamert5.exe": {
            "game": "bo1",
            "ticks": 0x1679870,
            "round_change": 0x165695D,
            "map": 0x2162950,
            "x": 0x1679710,
        },
        "plutonium-bootstrapper-win32.exe": {
            "game": "bo1",
            "ticks": 0x1679870,
            "round_change": 0x165695D,
            "map": 0x2162950,
            "x": 0x1679710,
        },
    }

    target_processes = list(OFFSETS_CONFIG.keys())

    reader = None
    is_timer_running = False

    while True:
      if not reader or not reader.h_process:
        self.root.after(
            0,
            lambda: self.asl_lbl.config(
                text="Searching for BO1 / BO3 process...", fg="#ffaa00"
            ),
        )

        found_reader = None
        for proc_name in target_processes:
          test_reader = MemoryReader(proc_name)
          if test_reader.attach():
            found_reader = test_reader
            break

        if not found_reader:
          time.sleep(1.5)
          continue

        if reader:
          reader.close()

        reader = found_reader
        print(f"[MemoryListener] Successfully hooked onto PID {reader.pid} ({reader.process_name})")
        self.root.after(
            0,
            lambda: self.asl_lbl.config(
                text=f"Attached to {reader.process_name}", fg="#00ffcc"
            ),
        )

      profile = OFFSETS_CONFIG.get(reader.process_name, {"game": "bo3"})
      game_type = profile["game"]

      if game_type == "bo1":
        base_addr = reader.get_module_base(reader.process_name)
        if base_addr == 0:
          base_addr = reader.get_module_base("BlackOps.exe")
        if base_addr == 0:
          base_addr = 0x00400000
      else:
        base_addr = reader.get_module_base("blackops3.exe")
        if base_addr == 0:
          base_addr = reader.get_module_base("boiii.exe")
        if base_addr == 0:
          base_addr = reader.get_module_base(reader.process_name)
        if base_addr == 0:
          base_addr = 0x140000000

      self.root.after(
          0,
          lambda: self.asl_lbl.config(
              text=f"Monitoring memory ({reader.process_name}) [{game_type.upper()}]", fg="#55ff55"
          ),
      )

      bo1_step = 0
      bo1_offset = 0
      old_round_change = None
      old_ticks = 0
      last_round = -1

      while reader.h_process:
        time.sleep(0.05)

        exit_code = wintypes.DWORD()
        if not reader.kernel32.GetExitCodeProcess(reader.h_process, ctypes.byref(exit_code)) or exit_code.value != 259:
          print("[MemoryListener] Process lost/disconnected.")
          reader.close()
          reader = None
          is_timer_running = False
          self.root.after(
              0,
              lambda: self.asl_lbl.config(
                  text="Game disconnected. Re-scanning...", fg="#ff5555"
              ),
          )
          break

        if game_type == "bo1":
          if not hasattr(self, "_bo1_step"):
            self._bo1_step = 0
            self._bo1_offset = 0
            self._old_round_change = None
            self._old_ticks = 0

          ticks_val = reader.read_int32(base_addr + profile["ticks"])
          if ticks_val is None:
            ticks_val = 0

          rc_byte = reader.read_byte(base_addr + profile["round_change"])
          if rc_byte is None:
            rc_byte = 0
          round_change_val = (rc_byte != 0)

          x_val = reader.read_float(base_addr + profile["x"])
          if x_val is None:
            x_val = 0.0

          map_name = ""
          try:
            buf = ctypes.create_string_buffer(32)
            bytes_read = ctypes.c_size_t()
            if reader.kernel32.ReadProcessMemory(
                reader.h_process, ctypes.c_void_p(base_addr + profile["map"]), buf, 32, ctypes.byref(bytes_read)
            ):
              map_name = buf.value.decode("utf-8", errors="ignore").split("\x00")[0].strip().lower()
          except Exception:
            map_name = ""

          if ticks_val <= 0 or ticks_val < self._old_ticks:
            if is_timer_running:
              is_timer_running = False
              self.root.after(0, self.sr_reset_timer)
            self._bo1_step = 0
            self._bo1_offset = 0
            self._old_round_change = None
            self._old_ticks = ticks_val
            self.root.after(
                0,
                lambda: self.asl_lbl.config(text="BO1 In Menu / Lobby", fg="#888888"),
            )
            continue

          if not is_timer_running and ticks_val > 0:
            is_timer_running = True
            self._bo1_offset = 2 if "zombie_moon" in map_name else 0
            self._bo1_step = (2 + self._bo1_offset) if not round_change_val else (3 + self._bo1_offset)
            self._old_round_change = round_change_val
            self.root.after(0, self.sr_start_timer_only)

          if is_timer_running:
            if self._old_round_change is not None and round_change_val != self._old_round_change:
              self._bo1_step += 1
              if self._bo1_step == 1:
                self._bo1_offset = 2 if "zombie_moon" in map_name else 0
              
              target_step = 8 + self._bo1_offset
              if self._bo1_step >= target_step:
                if self._bo1_offset == 2 and x_val > 13000:
                  self._bo1_step = 0
                else:
                  self.root.after(0, self.sr_split_action)
                  self._bo1_step = 4 + self._bo1_offset

              self._old_round_change = round_change_val

          self._old_ticks = ticks_val

          game_time_sec = (ticks_val * 50) / 1000.0
          if is_timer_running:
            self.timer_start_ticks = time.time() - game_time_sec

          status_msg = f"BO1 Active | Step: {self._bo1_step} | Ticks: {ticks_val}"
          self.root.after(
              0,
              lambda m=status_msg: self.asl_lbl.config(text=m, fg="#55ff55"),
          )

        else:
          map_name = ""
          try:
            buf = ctypes.create_string_buffer(32)
            bytes_read = ctypes.c_size_t()
            if reader.kernel32.ReadProcessMemory(
                reader.h_process, ctypes.c_void_p(base_addr + profile.get("map", 0x179DF840)), buf, 32, ctypes.byref(bytes_read)
            ):
              map_name = buf.value.decode("utf-8", errors="ignore").split("\x00")[0].strip().lower()
          except Exception:
            map_name = ""

          if not hasattr(self, "_bo3_map_offset"):
            self._bo3_map_offset = 8.0 if map_name == "zm_cosmodrome" else 0.0

          round_val = reader.read_int32(base_addr + profile["round"])
          if round_val is None or round_val < 0 or round_val > 255:
            abs_val = reader.read_int32(profile["round"])
            if abs_val is not None and 0 <= abs_val <= 255:
              round_val = abs_val
            else:
              round_val = 0

          level_time_val = reader.read_int32(base_addr + profile["level_time"])
          if level_time_val is None:
            level_time_val = reader.read_int32(profile["level_time"]) or 0
          
          game_time_sec = max(0.0, level_time_val / 1000.0) + getattr(self, "_bo3_map_offset", 0.0)

          paused_val = reader.read_int32(base_addr + profile["is_paused"])
          if paused_val is None:
            paused_val = reader.read_int32(profile["is_paused"]) or 0

          is_paused = (paused_val == 1)
          self.is_paused = is_paused
          self.update_drag_bar_visibility(is_paused)

          if 1 <= round_val <= 255:
            status_msg = (
                f"Active: Round {round_val}"
                if not is_paused
                else f"Paused: Round {round_val}"
            )
            self.root.after(
                0,
                lambda m=status_msg, p=is_paused: self.asl_lbl.config(
                    text=m, fg="#ffaa00" if p else "#55ff55"
                ),
            )

            if is_paused:
              continue

            if last_round <= 0:
              last_round = round_val
              if not is_timer_running:
                is_timer_running = True
                if round_val > 1:
                  self.root.after(0, lambda r=round_val, t=game_time_sec: self.sr_catch_up_to_round(r, t))
                else:
                  self.root.after(0, lambda t=game_time_sec: self.sr_start_timer_only(t))
            elif round_val > last_round:
              last_round = round_val
              if is_timer_running:
                self.root.after(0, self.sr_split_action)
          else:
            if last_round > 0 or is_timer_running:
              is_timer_running = False
              self.root.after(0, self.sr_reset_timer)
              
            last_round = 0
            if hasattr(self, "_bo3_map_offset"):
              delattr(self, "_bo3_map_offset")

            self.root.after(
                0,
                lambda: self.asl_lbl.config(
                    text=f"In Menu / Lobby (Val: {round_val})", fg="#888888"
                ),
            )

  def sr_generate_splits(self):
    target = 255

    self.splits_list = []
    for r in range(2, target + 1):
      self.splits_list.append({
          "name": f"Round {r}",
          "completed": False,
          "total_time": None,
          "segment_time": None,
          "delta_str": "",
          "pb_total": (r - 1) * 60.0,
      })

    self.current_split_index = 0
    self.loaded_lss_filename = "Default Generator"
    if hasattr(self, "lss_status_lbl"):
      self.lss_status_lbl.config(
          text=f"Splits: {self.loaded_lss_filename}", fg="#888888"
      )
    self.update_sr_substat_display()
    self.rebuild_sr_splits_ui()

  def sr_generate_splits(self):
        target = 255

        self.splits_list = []
        for r in range(2, target + 1):
            self.splits_list.append({
                "name": f"Round {r}",
                "completed": False,
                "total_time": None,
                "segment_time": None,
                "delta_str": "",
                "pb_total": (r - 1) * 60.0,
            })

        self.current_split_index = 0
        self.loaded_lss_filename = "Default Generator"
        if hasattr(self, "lss_status_lbl"):
            self.lss_status_lbl.config(
                text=f"Splits: {self.loaded_lss_filename}", fg="#888888"
            )
        self.update_sr_substat_display()
        self.rebuild_sr_splits_ui()

  def rebuild_sr_splits_ui(self):
      accent_hex = self.get_accent_hex()
      is_topmost = self.sr_topmost_var.get()
      TRANS_COLOR = "#000002"
      show_sph = self.sr_show_sph.get()
      current_font = self.timer_font_var.get() if hasattr(self, "timer_font_var") else "Segoe UI"

      if hasattr(self, "hdr_sph_lbl") and self.hdr_sph_lbl.winfo_exists():
          if show_sph:
              self.hdr_sph_lbl.pack(side="right", padx=4)
          else:
              self.hdr_sph_lbl.pack_forget()

      current_elapsed = 0.0
      if self.timer_running:
          current_elapsed = (
              time.time() - self.timer_start_ticks - self.elapsed_paused_time
          )

      max_visible = 7
      total_splits = len(self.splits_list)
      if self.current_split_index < max_visible - 1:
          start_idx = 0
      else:
          start_idx = self.current_split_index - max_visible + 1
      end_idx = min(total_splits, start_idx + max_visible)
      visible_splits_slice = self.splits_list[start_idx:end_idx]

      if hasattr(self, "sr_canvas") and self.sr_canvas.winfo_exists():
          self.sr_canvas.config(height=len(visible_splits_slice) * 31)

      for widget in self.sr_splits_container.winfo_children():
          widget.destroy()

      for row_idx, (actual_idx, split) in enumerate(
          enumerate(visible_splits_slice, start=start_idx)
      ):
          is_active = (
              actual_idx == self.current_split_index
              and self.timer_running
              and not split["completed"]
          )

          if is_active:
              row_bg = f"#{int(self.accent_rgb[0]*0.4):02x}{int(self.accent_rgb[1]*0.4):02x}{int(self.accent_rgb[2]*0.4):02x}"
          else:
              row_bg = (
                  TRANS_COLOR
                  if is_topmost
                  else ("#181818" if row_idx % 2 == 0 else "#1e1e1e")
              )

          row_frame = tk.Frame(self.sr_splits_container, bg=row_bg, padx=8, pady=6)
          row_frame.pack(fill="x", pady=1)
          row_frame.bind("<Button-3>", self.show_timer_context_menu)
          row_frame.bind("<Double-Button-1>", lambda e: self.toggle_game_mode_double_click())

          name_lbl = tk.Label(
              row_frame,
              text=split["name"],
              font=(current_font, 11, "bold" if is_active else "normal"),
              fg=accent_hex,
              bg=row_bg,
              width=12,
              anchor="w",
          )
          name_lbl.pack(side="left")
          name_lbl.bind("<Button-3>", self.show_timer_context_menu)
          name_lbl.bind("<Double-Button-1>", lambda e: self.toggle_game_mode_double_click())

          if split["completed"]:
              t_str = self.format_time(split["total_time"])
          else:
              t_str = (
                  self.format_time(split["pb_total"])
                  if actual_idx >= self.current_split_index
                  else "--"
              )

          time_lbl = tk.Label(
              row_frame,
              text=t_str,
              font=(current_font, 10, "bold"),
              fg="#ffffff",
              bg=row_bg,
              width=9,
              anchor="e",
          )
          time_lbl.pack(side="right")
          time_lbl.bind("<Button-3>", self.show_timer_context_menu)
          time_lbl.bind("<Double-Button-1>", lambda e: self.toggle_game_mode_double_click())

          if split["completed"]:
              d_str = split.get("delta_str", "")
          elif actual_idx == self.current_split_index and self.timer_running:
              prev_total = (
                  self.splits_list[actual_idx - 1]["total_time"]
                  if actual_idx > 0
                  else 0.0
              )
              live_seg_elapsed = current_elapsed - prev_total
              prev_pb_total = (
                  self.splits_list[actual_idx - 1]["pb_total"]
                  if actual_idx > 0
                  else 0.0
              )
              pb_seg = split["pb_total"] - prev_pb_total
              live_delta = live_seg_elapsed - pb_seg
              d_str = f"+{live_delta:.1f}" if live_delta >= 0 else f"{live_delta:.1f}"
          else:
              d_str = ""

          d_fg = "#55ff55" if d_str.startswith("-") else "#ff5555"
          delta_lbl = tk.Label(
              row_frame,
              text=d_str,
              font=(current_font, 9),
              fg=d_fg,
              bg=row_bg,
              width=7,
              anchor="e",
          )
          delta_lbl.pack(side="right", padx=6)
          delta_lbl.bind("<Button-3>", self.show_timer_context_menu)
          delta_lbl.bind("<Double-Button-1>", lambda e: self.toggle_game_mode_double_click())

          if split["completed"]:
              seg_str = self.format_time_short(split["segment_time"])
              seg_fg = "#aaaaaa"
          else:
              prev_pb_total = (
                  self.splits_list[actual_idx - 1]["pb_total"]
                  if actual_idx > 0
                  else 0.0
              )
              pb_seg = split["pb_total"] - prev_pb_total
              seg_str = self.format_time_short(pb_seg)
              seg_fg = "#666666" if actual_idx > self.current_split_index else "#ffffff"

          seg_lbl = tk.Label(
              row_frame,
              text=seg_str,
              font=(current_font, 9),
              fg=seg_fg,
              bg=row_bg,
              width=8,
              anchor="e",
          )
          seg_lbl.pack(side="right")
          seg_lbl.bind("<Button-3>", self.show_timer_context_menu)
          seg_lbl.bind("<Double-Button-1>", lambda e: self.toggle_game_mode_double_click())

          if show_sph:
              sph_str = ""
              sph_color = "#55ff55"
              if split["completed"] and split["segment_time"] is not None:
                  match = re.search(r"\d+", split["name"])
                  r_num = int(match.group()) if match else (actual_idx + 2)
                  zombies = self.get_zombies_for_round(r_num, int(self.players_spin.get() if hasattr(self, "players_spin") else 1))
                  hordes = zombies / 24.0
                  if hordes > 0:
                      sph_val = split["segment_time"] / hordes
                      sph_str = f"{sph_val:.1f}"
                      if sph_val <= 5.0:
                          sph_color = "#55ff55"
                      elif sph_val <= 7.0:
                          sph_color = "#ffff55"
                      else:
                          sph_color = "#ff5555"

              sph_lbl = tk.Label(
                  row_frame,
                  text=sph_str,
                  font=(current_font, 9, "bold"),
                  fg=sph_color,
                  bg=row_bg,
                  width=7,
                  anchor="e",
              )
              sph_lbl.pack(side="right", padx=4)
              sph_lbl.bind("<Button-3>", self.show_timer_context_menu)
              sph_lbl.bind("<Double-Button-1>", lambda e: self.toggle_game_mode_double_click())

  def sr_split_action(self):
      now = time.time()
      if not self.timer_running:
          self.timer_running = True
          self.timer_paused = False
          self.timer_start_ticks = now
          self.elapsed_paused_time = 0.0
          self.current_split_index = 0
          self.sr_start_btn.config(text="Split")
      else:
          if self.current_split_index < len(self.splits_list):
              total_elapsed = now - self.timer_start_ticks - self.elapsed_paused_time

              prev_total = (
                  self.splits_list[self.current_split_index - 1]["total_time"]
                  if self.current_split_index > 0
                  else 0.0
              )
              seg_time = total_elapsed - prev_total

              split = self.splits_list[self.current_split_index]
              split["completed"] = True
              split["total_time"] = total_elapsed
              split["segment_time"] = seg_time

              prev_pb_total = (
                  self.splits_list[self.current_split_index - 1]["pb_total"]
                  if self.current_split_index > 0
                  else 0.0
              )
              pb_seg = split["pb_total"] - prev_pb_total
              delta = seg_time - pb_seg
              split["delta_str"] = f"+{delta:.1f}" if delta >= 0 else f"{delta:.1f}"

              self.current_split_index += 1
              if self.current_split_index >= len(self.splits_list):
                  self.timer_running = False
                  self.sr_start_btn.config(text="Finished")

      self.update_sr_substat_display()
      self.rebuild_sr_splits_ui()

  def sr_undo_split(self):
      if self.current_split_index > 0:
          self.current_split_index -= 1
          split = self.splits_list[self.current_split_index]
          split["completed"] = False
          split["total_time"] = None
          split["segment_time"] = None
          split["delta_str"] = ""
          self.timer_running = True
          self.sr_start_btn.config(text="Split")
          self.update_sr_substat_display()
          self.rebuild_sr_splits_ui()

  def sr_reset_timer(self):
      self.timer_running = False
      self.timer_paused = False
      self._bo1_initialized = False
      self._old_round_change = None
      self._old_ticks = 0
      self._bo1_flips = 0
      self._bo1_step = 0
      self._bo1_offset = 0
      if hasattr(self, "_bo3_map_offset"):
          delattr(self, "_bo3_map_offset")
      self.current_split_index = 0
      for split in self.splits_list:
          split["completed"] = False
          split["total_time"] = None
          split["segment_time"] = None
          split["delta_str"] = ""
      self.sr_start_btn.config(text="Start / Split")
      self.sr_total_time_lbl.config(text="00:00:00")
      self.sr_current_seg_lbl.config(text="00:00.0")
      self.update_sr_substat_display()
      self.rebuild_sr_splits_ui()

  def sr_start_timer_only(self, game_time_seconds=0.0):
      if not self.timer_running:
          self.timer_running = True
          self.timer_paused = False
          self.timer_start_ticks = time.time() - game_time_seconds
          self.elapsed_paused_time = 0.0
          self.current_split_index = 0
          if hasattr(self, "sr_start_btn"):
              self.sr_start_btn.config(text="Split")
          self.update_sr_substat_display()
          self.rebuild_sr_splits_ui()

  def start_timer_loop(self):
      def loop():
          last_time = time.time()
          while True:
              now = time.time()
              delta_time = now - last_time
              last_time = now

              if getattr(self, "is_paused", False):
                  if self.timer_running and not self.timer_paused:
                      self.timer_paused = True
                  self.elapsed_paused_time += delta_time
              else:
                  if self.timer_paused:
                      self.timer_paused = False

              if self.timer_running and not getattr(self, "is_paused", False):
                  elapsed = now - self.timer_start_ticks - self.elapsed_paused_time
                  t_str = self.format_time_long(elapsed)

                  prev_total = (
                      self.splits_list[self.current_split_index - 1]["total_time"]
                      if self.current_split_index > 0
                      else 0.0
                  )
                  seg_elapsed = elapsed - prev_total
                  seg_str = self.format_time_short(seg_elapsed)

                  active_split = self.splits_list[self.current_split_index] if self.current_split_index < len(self.splits_list) else None
                  d_str = ""
                  d_fg = "#ff5555"
                  if active_split:
                      prev_pb_total = (
                          self.splits_list[self.current_split_index - 1]["pb_total"]
                          if self.current_split_index > 0
                          else 0.0
                      )
                      pb_seg = active_split["pb_total"] - prev_pb_total
                      live_delta = seg_elapsed - pb_seg
                      d_str = f"+{live_delta:.1f}" if live_delta >= 0 else f"{live_delta:.1f}"
                      d_fg = "#55ff55" if d_str.startswith("-") else "#ff5555"

                  try:
                      self.sr_total_time_lbl.config(text=t_str)
                      self.sr_current_seg_lbl.config(text=seg_str)
                      
                      if active_split:
                          for row_frame in self.sr_splits_container.winfo_children():
                              children = row_frame.winfo_children()
                              if len(children) >= 3:
                                  name_lbl = children[0]
                                  if name_lbl.cget("text") == active_split.get("name", ""):
                                      children[2].config(text=d_str, fg=d_fg)
                                      break
                  except Exception:
                      pass

              time.sleep(0.05)

      t = threading.Thread(target=loop, daemon=True)
      t.start()

  def sr_catch_up_to_round(self, target_round, game_time_seconds=None):
      if not self.timer_running:
          self.timer_running = True
          self.timer_paused = False
          self.current_split_index = 0
          if hasattr(self, "sr_start_btn"):
              self.sr_start_btn.config(text="Split")

      while self.current_split_index < len(self.splits_list):
          split = self.splits_list[self.current_split_index]
          match = re.search(r"\d+", split["name"])
          if match:
              split_round_num = int(match.group())
              if split_round_num <= target_round:
                  split["completed"] = True
                  prev_total = (
                      self.splits_list[self.current_split_index - 1]["total_time"]
                      if self.current_split_index > 0
                      else 0.0
                  )
                  
                  if game_time_seconds is not None and split_round_num == target_round:
                      seg_time = max(0.0, game_time_seconds - prev_total)
                      split["total_time"] = game_time_seconds
                  else:
                      seg_time = split["pb_total"] - (
                          self.splits_list[self.current_split_index - 1]["pb_total"]
                          if self.current_split_index > 0
                          else 0.0
                      )
                      split["total_time"] = prev_total + seg_time

                  split["segment_time"] = seg_time
                  split["delta_str"] = "0.0"
                  
                  self.current_split_index += 1
              else:
                  break
          else:
              break

      if game_time_seconds is not None:
          self.elapsed_paused_time = 0.0
          self.timer_start_ticks = time.time() - game_time_seconds
      else:
          completed_total = 0.0
          if self.current_split_index > 0 and self.splits_list[self.current_split_index - 1]["total_time"] is not None:
              completed_total = self.splits_list[self.current_split_index - 1]["total_time"]
          self.elapsed_paused_time = 0.0
          self.timer_start_ticks = time.time() - completed_total

      if self.current_split_index >= len(self.splits_list):
          self.timer_running = False
          if hasattr(self, "sr_start_btn"):
              self.sr_start_btn.config(text="Finished")

      self.update_sr_substat_display()
      self.rebuild_sr_splits_ui()

  def format_time(self, seconds):
      if seconds is None:
          return "--"
      m = int(seconds // 60)
      s = seconds % 60
      return (
          f"{m:02d}:{s:05.2f}"
          if m < 60
          else f"{int(m//60)}:{m%60:02d}:{s:05.2f}"
      )

  def format_time_long(self, seconds):
      h = int(seconds // 3600)
      m = int((seconds % 3600) // 60)
      s = int(seconds % 60)
      if h > 0:
          return f"{h:02d}:{m:02d}:{s:02d}"
      else:
          ms = int((seconds % 1) * 10)
          return f"{m:02d}:{s:02d}.{ms}" if seconds < 60 else f"{m:02d}:{s:02d}"

  def format_time_short(self, seconds):
      if seconds is None:
          return ""
      m = int(seconds // 60)
      s = seconds % 60
      if m > 0:
          return f"{m}:{s:04.1f}"
      else:
          return f"{s:04.1f}"

  def update_speedrun_ui(self):
      accent_hex = self.get_accent_hex()
      self.sr_start_btn.config(bg=accent_hex)
      self.sr_total_time_lbl.config(fg=accent_hex)
      self.sr_current_seg_lbl.config(fg=accent_hex)
      self.rebuild_sr_splits_ui()


if __name__ == "__main__":
  root = tk.Tk()
  app = ZombiesTrackerApp(root)
  root.mainloop()
