husk:
	gcc poc-husk.c -o husk

loona:
  # disabled ssp for simplicity but it works with ssp enabled
	gcc poc-loona.c -o loona -fno-stack-protector
