import gin

from trainer import components

gin.parse_config_file("config.gin")
print(components)
