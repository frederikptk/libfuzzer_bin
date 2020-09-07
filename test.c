#include <stdio.h>

int test(int a, int b, int c) {
	if (a == b) return c;
	
	for (int i = 0; i < 10; i++) {
		if (a == 1) continue;
		if (a == 2) {
			return 10;
		}
		if (a == 3) {
			if (b == 4) {
				c++;
			}
		}
		b++;
	}
	
	return a + b + c;
}

int main() {
	test(1, 2, 3);
	return 0;
}
