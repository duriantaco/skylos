using System.Threading.Tasks;

namespace Shop.Services;

public class BasketState
{
    private int _count;

    public Task CheckoutAsync()
    {
        _count = 0;
        return Task.CompletedTask;
    }

    public int OrphanCount()
    {
        return _count;
    }

    public int RetiredTotal()
    {
        return _count * 2;
    }
}
