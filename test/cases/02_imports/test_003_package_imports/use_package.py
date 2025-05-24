import package
from package import package_function, ExportedClass

def main():
    """Main function that uses package imports."""
    print(f"Package constant: {package.PACKAGE_CONSTANT}")
    
    result1 = package.package_level_function()
    print(f"Package function result: {result1}")
    
    result2 = package_function()
    print(f"Re-exported function result: {result2}")
    
    obj = ExportedClass()
    result3 = obj.method()
    print(f"Re-exported class method result: {result3}")
    
    return "All package features used successfully"

if __name__ == "__main__":
    main()