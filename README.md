# EasyCook4
A simple Python application designed to streamline asset cooking for Unreal Engine 4, primarily for modding purposes.

![preview](preview.png)

## Why bother?
Traditionally, cooking assets in Unreal relies on placing the assets you want cooked into maps, then specifying that map in the cooking process, this often results in unnecessary cooking of additional shaders, assets, and other content you don’t actually need. This wastes both **time** and **resources**.

**EasyCook** solves this by letting you specify exactly which assets or folders to cook. With its convenient GUI, you can:
* Select only what you need to cook nothing extra.
* Save and load profiles to avoid retyping commands or digging through old messages.
* Speed up your workflow and focus on modding, not setup.

## Installation
* **Executable Release**: A prebuilt `.exe` is available in Releases. This version does **not** require Python to be installed.
* **Python Script**: If you’d like to run or modify the source directly, you can execute the Python script. For this option, you’ll need a local Python installation.

## How to add to cook list

## Adding a Single Asset

1. In Unreal, copy the package path of the asset you want to cook.
   * Example from the Content Browser:
     ```
     /Game/Data/MissionDataTable
     ```
   * Or reference strings like:
     ```
     DataTable'/Game/Data/MissionDataTable.MissionDataTable'
     ```
     EasyCook will normalize this to `/Game/Data/MissionDataTable`.

2. In EasyCook:
   * Paste the path into the input box at the top of the **Cook List** panel.
   * Click **Add Asset** (or use **Paste & Add** if you already copied it).

3. The asset will appear in the list, e.g.:
   ```
   /Game/Data/MissionDataTable
   ```

## Adding a Folder

1. Click **Add Folder…** under the Cook List.
2. Choose a folder inside your project’s `Content/` directory.
3. EasyCook will resolve it into a `/Game/...` path and add it to the list as:
   ```
   /Game/Data
   ```
   This represents all assets inside that folder.
> Note: When you **Run Cook** or **Copy Command**, EasyCook will expand that folder behind the scenes into every `.uasset` inside.

## Tips
* You can mix individual assets and folders in the same list.
* Duplicate entries are ignored.
* For maps (`.umap`), just add them like any other asset and it will work. This means you can have multiple maps
* Use **Save** to store your current list, settings, and paths. Use **Load** to restore them later.

## Credits
- [TraoX1](https://github.com/TraoX1)
